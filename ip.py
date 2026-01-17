import subprocess
import random
import ipaddress
import requests
import os
import json
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

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
DATA_DIR = "data"

HTTPS_PORTS = [443, 8443, 2053, 2083, 2087, 2096]

REGION_WHITELIST = {
    "HK", "SG", "JP", "KR",
    "US", "DE", "UK",
    "TW", "AU", "CA"
}

MAX_OUTPUT_PER_REGION = 32
HISTORY_DAYS = 7

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
# 工具函数
# =========================

def ensure_dirs():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(DATA_DIR, exist_ok=True)

def cleanup_old_history():
    now = datetime.utcnow()
    for fn in os.listdir(DATA_DIR):
        if not fn.startswith("ip_raw_") or not fn.endswith(".json"):
            continue
        try:
            date_str = fn.replace("ip_raw_", "").replace(".json", "")
            dt = datetime.strptime(date_str, "%Y-%m-%d")
            if now - dt > timedelta(days=HISTORY_DAYS):
                os.remove(os.path.join(DATA_DIR, fn))
        except Exception:
            continue

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
            "--connect-timeout", str(CONNECT_TIMEOUT),
            "--max-time", str(TIMEOUT),
            "--resolve", f"{domain}:443:{ip}",
            f"https://{domain}"
        ]

        out = subprocess.check_output(cmd, timeout=TIMEOUT + 1)
        tc, ta, code = out.decode().strip().split()
        latency = int((float(tc) + float(ta)) * 1000)

        if latency > LATENCY_LIMIT or code == "000":
            return None

        hdr = subprocess.check_output(
            ["curl", "-sI", "--resolve", f"{domain}:443:{ip}", f"https://{domain}"],
            timeout=TIMEOUT
        ).decode(errors="ignore").lower()

        ray = next((l.split(":")[1].strip() for l in hdr.splitlines() if l.startswith("cf-ray")), None)
        if not ray:
            return None

        colo = ray.split("-")[-1].upper()
        region = COLO_MAP.get(colo, "UNMAPPED")

        return {
            "ip": str(ip),
            "domain": domain,
            "view": domain,
            "colo": colo,
            "region": region,
            "latency": latency
        }
    except Exception:
        return None

def score_ip(latencies, total_views):
    p = len(latencies)
    if p < 2:
        return 0

    stability = p / total_views
    consistency = 1 - (max(latencies) - min(latencies)) / LATENCY_LIMIT
    consistency = max(consistency, 0.3)
    latency_score = 1 / (1 + min(latencies) / 100)

    return round(stability * consistency * latency_score, 4)

# =========================
# 主流程
# =========================

def main():
    ensure_dirs()
    cleanup_old_history()

    cidrs = fetch_cf_ipv4_cidrs()
    ips = weighted_random_ips(cidrs, SAMPLE_SIZE)

    raw_results = []

    with ThreadPoolExecutor(MAX_WORKERS) as pool:
        for batch in pool.map(lambda ip: [r for d in TRACE_DOMAINS.values() if (r := curl_test(ip, d))], ips):
            raw_results.extend(batch)

    # === 保存历史 raw ===
    today = datetime.utcnow().strftime("%Y-%m-%d")
    with open(f"{DATA_DIR}/ip_raw_{today}.json", "w") as f:
        json.dump(raw_results, f, indent=2)

    # === 聚合评分 ===
    ip_map = defaultdict(list)
    for r in raw_results:
        ip_map[r["ip"]].append(r)

    candidates = []
    region_files = defaultdict(list)
    all_txt = []

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
            "score": score
        }
        candidates.append(node)

    candidates.sort(key=lambda x: x["score"], reverse=True)

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

    with open(f"{OUTPUT_DIR}/ip_all.json", "w") as f:
        json.dump(raw_results, f, indent=2)

    with open(f"{OUTPUT_DIR}/ip_candidates.json", "w") as f:
        json.dump({
            "meta": {
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "views": list(TRACE_DOMAINS.values())
            },
            "nodes": candidates
        }, f, indent=2)

    print("[*] Done.")

if __name__ == "__main__":
    main()