import subprocess
import random
import ipaddress
import requests
import os
import json
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# =========================
# 基础参数
# =========================

CF_IPS_V4_URL = "https://www.cloudflare.com/ips-v4"

TRACE_DOMAINS = {
    "v0": "sptest.ittool.pp.ua",
    "v1": "sptest1.ittool.pp.ua",
    "v2": "sptest2.ittool.pp.ua",
}

SAMPLE_SIZE = 800
TIMEOUT = 4
CONNECT_TIMEOUT = 2
MAX_WORKERS = 30
LATENCY_LIMIT = 800

OUTPUT_DIR = "public"
HTTPS_PORTS = [443, 8443, 2053, 2083, 2087, 2096]

REGION_WHITELIST = {
    "HK", "SG", "JP", "KR",
    "US", "DE", "UK",
    "TW", "AU", "CA"
}

MAX_OUTPUT_PER_REGION = 32

# =========================
# COLO → Region
# =========================

COLO_MAP = {
    "HKG": "HK", "SIN": "SG", "NRT": "JP", "KIX": "JP",
    "ICN": "KR", "TPE": "TW",
    "SYD": "AU", "MEL": "AU",

    "LAX": "US", "SJC": "US", "SFO": "US",
    "SEA": "US", "ORD": "US", "DFW": "US",
    "ATL": "US", "IAD": "US", "EWR": "US",
    "JFK": "US", "BOS": "US", "MIA": "US",

    "FRA": "DE", "MUC": "DE",
    "LHR": "UK", "LGW": "UK",

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

def curl_test(ip, domain):
    try:
        cmd = [
            "curl",
            "-o", "/dev/null",
            "-s",
            "-w", "%{time_connect} %{time_appconnect} %{http_code}",
            "--http1.1",
            "--tlsv1.3",
            "--connect-timeout", str(CONNECT_TIMEOUT),
            "--max-time", str(TIMEOUT),
            "--resolve", f"{domain}:443:{ip}",
            f"https://{domain}"
        ]

        out = subprocess.check_output(cmd, timeout=TIMEOUT + 1)
        parts = out.decode().strip().split()

        if len(parts) != 3:
            return None

        time_connect, time_appconnect, http_code = parts
        latency = int((float(time_connect) + float(time_appconnect)) * 1000)

        if latency > LATENCY_LIMIT or http_code == "000":
            return None

        # 再拉一次 header 取 cf-ray
        hdr = subprocess.check_output(
            [
                "curl", "-sI",
                "--resolve", f"{domain}:443:{ip}",
                f"https://{domain}"
            ],
            timeout=TIMEOUT
        ).decode(errors="ignore").lower()

        ray = None
        for line in hdr.splitlines():
            if line.startswith("cf-ray"):
                ray = line.split(":")[1].strip()
                break

        if not ray:
            return None

        colo = ray.split("-")[-1].upper()
        region = COLO_MAP.get(colo) or "UNMAPPED"

        return {
            "ip": str(ip),
            "domain": domain,
            "colo": colo,
            "region": region,
            "latency": latency
        }

    except Exception:
        return None

def score_ip(latencies, total_views):
    P = len(latencies)
    if P < 2:
        return 0

    S_stability = P / total_views

    lat_min = min(latencies)
    lat_max = max(latencies)

    S_consistency = 1 - (lat_max - lat_min) / LATENCY_LIMIT
    S_consistency = max(0.3, S_consistency)

    S_latency = 1 / (1 + lat_min / 100)

    return round(S_stability * S_consistency * S_latency, 4)

def test_ip(ip):
    records = []

    for view, domain in TRACE_DOMAINS.items():
        r = curl_test(ip, domain)
        if r:
            r["view"] = view
            records.append(r)

    return records

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    cidrs = fetch_cf_ipv4_cidrs()
    ips = weighted_random_ips(cidrs, SAMPLE_SIZE)

    raw_results = []

    with ThreadPoolExecutor(MAX_WORKERS) as pool:
        for batch in pool.map(test_ip, ips):
            raw_results.extend(batch)

    # 按 IP 聚合
    ip_map = defaultdict(list)
    for r in raw_results:
        ip_map[r["ip"]].append(r)

    candidates = []
    all_txt = []
    region_files = defaultdict(list)

    for ip, items in ip_map.items():
        latencies = [x["latency"] for x in items]
        score = score_ip(latencies, len(TRACE_DOMAINS))

        if score <= 0:
            continue

        best = min(items, key=lambda x: x["latency"])

        node = {
            "ip": ip,
            "port": random.choice(HTTPS_PORTS),
            "region": best["region"],
            "colo": best["colo"],
            "latencies": latencies,
            "views_passed": [x["view"] for x in items],
            "score": score
        }

        candidates.append(node)

    candidates.sort(key=lambda x: x["score"], reverse=True)

    # 输出 TXT
    for n in candidates:
        line = f'{n["ip"]}:{n["port"]}#{n["region"]}-score{n["score"]}\n'
        all_txt.append(line)

        if n["region"] in REGION_WHITELIST:
            region_files[n["region"]].append(line)

    with open(f"{OUTPUT_DIR}/ip_all.txt", "w") as f:
        f.writelines(all_txt)

    for region, lines in region_files.items():
        with open(f"{OUTPUT_DIR}/ip_{region}.txt", "w") as f:
            f.writelines(lines[:MAX_OUTPUT_PER_REGION])

    # 输出 JSON
    with open(f"{OUTPUT_DIR}/ip_all.json", "w") as f:
        json.dump(raw_results, f, indent=2)

    with open(f"{OUTPUT_DIR}/ip_candidates.json", "w") as f:
        json.dump({
            "meta": {
                "views": list(TRACE_DOMAINS.keys()),
                "generated_at": datetime.utcnow().isoformat() + "Z"
            },
            "nodes": candidates
        }, f, indent=2)

    print("[*] Done.")

if __name__ == "__main__":
    main()