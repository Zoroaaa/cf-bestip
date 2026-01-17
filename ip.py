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
DATA_DIR = "data"

HTTPS_PORTS = [443, 8443, 2053, 2083, 2087, 2096]

REGION_WHITELIST = {
    "HK", "SG", "JP", "KR",
    "US", "DE", "UK",
    "TW", "AU", "CA"
}

MAX_OUTPUT_PER_REGION = 32
GOOD_SCORE_THRESHOLD = 0.785

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

        tc, ta, code = parts
        latency = int((float(tc) + float(ta)) * 1000)

        if latency > LATENCY_LIMIT or code == "000":
            return None

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
        region = COLO_MAP.get(colo, "UNMAPPED")

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

def aggregate_nodes(raw_results):
    ip_map = defaultdict(list)
    for r in raw_results:
        ip_map[r["ip"]].append(r)

    nodes = []
    for ip, items in ip_map.items():
        latencies = [x["latency"] for x in items]
        score = score_ip(latencies, len(TRACE_DOMAINS))
        if score <= 0:
            continue

        best = min(items, key=lambda x: x["latency"])
        nodes.append({
            "ip": ip,
            "port": random.choice(HTTPS_PORTS),
            "region": best["region"],
            "colo": best["colo"],
            "latencies": latencies,
            "views_passed": [x["view"] for x in items],
            "score": score
        })

    return nodes

# =========================
# REGION 增量逻辑
# =========================

def load_region_ips(region):
    path = f"{OUTPUT_DIR}/ip_{region}.txt"
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [line.split(":")[0] for line in f if line.strip()]

def retest_region_nodes(region):
    ips = load_region_ips(region)
    raw = []
    with ThreadPoolExecutor(MAX_WORKERS) as pool:
        for batch in pool.map(test_ip, ips):
            raw.extend(batch)
    return aggregate_nodes(raw)

def merge_region(old_nodes, new_nodes):
    pool = {}
    for n in old_nodes + new_nodes:
        pool[n["ip"]] = n
    merged = list(pool.values())
    merged.sort(key=lambda x: x["score"], reverse=True)
    return merged[:MAX_OUTPUT_PER_REGION]

# =========================
# 历史 & 高质量池
# =========================

def save_ip_all_history(lines):
    os.makedirs(DATA_DIR, exist_ok=True)
    today = datetime.utcnow().strftime("%Y-%m-%d")
    path = f"{DATA_DIR}/ip_all_{today}.txt"
    with open(path, "w") as f:
        f.writelines(lines)

    files = sorted(f for f in os.listdir(DATA_DIR) if f.startswith("ip_all_"))
    while len(files) > 7:
        os.remove(os.path.join(DATA_DIR, files.pop(0)))

def update_good_pool(nodes):
    path = "ip_good_pool.txt"
    pool = {}

    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                pool[line.split(":")[0]] = line

    for n in nodes:
        if n["score"] >= GOOD_SCORE_THRESHOLD:
            pool[n["ip"]] = f'{n["ip"]}:{n["port"]}#{n["region"]}-score{n["score"]}\n'

    with open(path, "w") as f:
        f.writelines(pool.values())

# =========================
# 主流程
# =========================

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    cidrs = fetch_cf_ipv4_cidrs()
    ips = weighted_random_ips(cidrs, SAMPLE_SIZE)

    raw = []
    with ThreadPoolExecutor(MAX_WORKERS) as pool:
        for batch in pool.map(test_ip, ips):
            raw.extend(batch)

    today_nodes = aggregate_nodes(raw)
    today_nodes.sort(key=lambda x: x["score"], reverse=True)

    all_lines = [
        f'{n["ip"]}:{n["port"]}#{n["region"]}-score{n["score"]}\n'
        for n in today_nodes
    ]

    with open(f"{OUTPUT_DIR}/ip_all.txt", "w") as f:
        f.writelines(all_lines)

    save_ip_all_history(all_lines)
    update_good_pool(today_nodes)

    region_new = defaultdict(list)
    for n in today_nodes:
        if n["region"] in REGION_WHITELIST:
            region_new[n["region"]].append(n)

    for region in REGION_WHITELIST:
        old_nodes = retest_region_nodes(region)
        merged = merge_region(old_nodes, region_new.get(region, []))

        with open(f"{OUTPUT_DIR}/ip_{region}.txt", "w") as f:
            for n in merged:
                f.write(f'{n["ip"]}:{n["port"]}#{region}-score{n["score"]}\n')

    with open(f"{OUTPUT_DIR}/ip_candidates.json", "w") as f:
        json.dump({
            "meta": {
                "generated_at": datetime.utcnow().isoformat() + "Z"
            },
            "nodes": today_nodes
        }, f, indent=2)

    print("[*] Done.")

if __name__ == "__main__":
    main()