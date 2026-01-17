import subprocess
import random
import ipaddress
import time
import requests
import os
import json
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

# =========================
# 参数区
# =========================

CF_IPS_V4_URL = "https://www.cloudflare.com/ips-v4"
TRACE_DOMAIN = "sptest.ittool.pp.ua"

SAMPLE_SIZE = 800
TIMEOUT = 4
MAX_WORKERS = 30
LATENCY_LIMIT = 800

OUTPUT_DIR = "public"

HTTPS_PORTS = [443, 8443, 2053, 2083, 2087, 2096]

# 允许输出的地区
REGION_WHITELIST = {
    "HK", "SG", "JP", "KR",
    "US", "DE", "UK",
    "TW", "AU", "CA"
}

# =========================
# Cloudflare Colo → Region
# =========================

COLO_MAP = {
    # Asia
    "HKG": "HK", "SIN": "SG", "NRT": "JP", "KIX": "JP",
    "ICN": "KR", "TPE": "TW", "BKK": "TH",
    "KUL": "MY", "MNL": "PH", "CGK": "ID",
    "SYD": "AU", "MEL": "AU",

    # US
    "LAX": "US", "SJC": "US", "SFO": "US",
    "SEA": "US", "ORD": "US", "DFW": "US",
    "ATL": "US", "IAD": "US", "EWR": "US",
    "JFK": "US", "BOS": "US", "MIA": "US",

    # Europe
    "FRA": "DE", "MUC": "DE",
    "LHR": "UK", "LGW": "UK",
    "AMS": "NL", "CDG": "FR",
    "MAD": "ES", "BCN": "ES",
    "MXP": "IT",

    # Others
    "YYZ": "CA", "YVR": "CA",
}

# =========================

def fetch_cf_ipv4_cidrs():
    r = requests.get(CF_IPS_V4_URL, timeout=10)
    r.raise_for_status()
    return [x.strip() for x in r.text.splitlines() if x.strip()]

def weighted_random_ips(cidrs, total):
    pools = []
    for c in cidrs:
        net = ipaddress.ip_network(c)
        pools.append((net, net.num_addresses))

    total_weight = sum(w for _, w in pools)
    result = []

    for net, weight in pools:
        cnt = max(1, int(total * weight / total_weight))
        hosts = list(net.hosts())
        if hosts:
            result.extend(random.sample(hosts, min(cnt, len(hosts))))

    random.shuffle(result)
    return result[:total]

def test_ip(ip):
    try:
        cmd = [
            "curl", "-sI",
            "--resolve", f"{TRACE_DOMAIN}:443:{ip}",
            f"https://{TRACE_DOMAIN}",
            "--max-time", str(TIMEOUT)
        ]
        start = time.time()
        out = subprocess.check_output(cmd, timeout=TIMEOUT + 1)
        latency = int((time.time() - start) * 1000)

        if latency > LATENCY_LIMIT:
            return None

        headers = out.decode(errors="ignore").lower()
        ray = None
        for line in headers.splitlines():
            if line.startswith("cf-ray"):
                ray = line.split(":")[1].strip()

        if not ray:
            return None

        colo = ray.split("-")[-1].upper()
        region = COLO_MAP.get(colo, "OTHER")

        return {
            "ip": str(ip),
            "port": random.choice(HTTPS_PORTS),
            "latency": latency,
            "colo": colo,
            "region": region
        }

    except:
        return None

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    cidrs = fetch_cf_ipv4_cidrs()
    ips = weighted_random_ips(cidrs, SAMPLE_SIZE)

    results = []
    with ThreadPoolExecutor(MAX_WORKERS) as pool:
        for r in pool.map(test_ip, ips):
            if r:
                results.append(r)

    results.sort(key=lambda x: x["latency"])

    region_files = defaultdict(list)

    # TXT + JSON
    all_txt = []
    for r in results:
        line = f'{r["ip"]}:{r["port"]}#{r["region"]}-{r["latency"]}ms\n'
        all_txt.append(line)

        if r["region"] in REGION_WHITELIST:
            region_files[r["region"]].append(line)

    with open(f"{OUTPUT_DIR}/ip_all.txt", "w") as f:
        f.writelines(all_txt)

    for region, lines in region_files.items():
        with open(f"{OUTPUT_DIR}/ip_{region}.txt", "w") as f:
            f.writelines(lines)

    with open(f"{OUTPUT_DIR}/ip_all.json", "w") as f:
        json.dump(results, f, indent=2)

    print("[*] Done.")

if __name__ == "__main__":
    main()