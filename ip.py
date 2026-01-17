import subprocess
import random
import ipaddress
import time
import requests
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

# =========================
# 基础参数
# =========================

CF_IPS_V4_URL = "https://www.cloudflare.com/ips-v4"
TRACE_DOMAIN = "sptest.ittool.pp.ua"   # 你的 cf-ray Worker 域名

SAMPLE_SIZE = 800          # 总抽样数量
TIMEOUT = 4
MAX_WORKERS = 30
LATENCY_LIMIT = 800        # ms

# 端口策略
HTTPS_PORTS = [443, 8443, 2053, 2083, 2087, 2096]

# 只生成这些地区的文件
REGION_WHITELIST = {"HK", "SG", "JP", "KR", "US", "DE", "UK"}

# cf-ray colo 映射
COLO_MAP = {
    "HKG": "HK",
    "SIN": "SG",
    "NRT": "JP",
    "KIX": "JP",
    "ICN": "KR",
    "LAX": "US",
    "SJC": "US",
    "FRA": "DE",
    "LHR": "UK"
}

# =========================

def fetch_cf_ipv4_cidrs():
    resp = requests.get(CF_IPS_V4_URL, timeout=10)
    resp.raise_for_status()
    return [line.strip() for line in resp.text.splitlines() if line.strip()]

def weighted_random_ips(cidrs, total):
    pools = []
    for cidr in cidrs:
        net = ipaddress.ip_network(cidr)
        pools.append((net, net.num_addresses))

    total_weight = sum(w for _, w in pools)
    result = []

    for net, weight in pools:
        count = max(1, int(total * weight / total_weight))
        hosts = list(net.hosts())
        if hosts:
            result.extend(random.sample(hosts, min(count, len(hosts))))

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

        headers = out.decode().lower()
        ray = None
        for line in headers.splitlines():
            if line.startswith("cf-ray"):
                ray = line.split(":")[1].strip()

        if not ray:
            return None

        colo = ray.split("-")[-1].upper()
        region = COLO_MAP.get(colo, colo)

        return ip, latency, region

    except:
        return None

def main():
    print("[*] Fetching Cloudflare IPv4 ranges...")
    cidrs = fetch_cf_ipv4_cidrs()

    print("[*] Sampling IPs...")
    ips = weighted_random_ips(cidrs, SAMPLE_SIZE)

    print(f"[*] Testing {len(ips)} IPs...")
    results = []
    with ThreadPoolExecutor(MAX_WORKERS) as pool:
        for r in pool.map(test_ip, ips):
            if r:
                results.append(r)

    results.sort(key=lambda x: x[1])

    print(f"[*] {len(results)} IPs passed")

    region_map = defaultdict(list)

    with open("ip_all.txt", "w") as f:
        for ip, latency, region in results:
            port = random.choice(HTTPS_PORTS)
            line = f"{ip}:{port}#{region}-{latency}ms\n"
            f.write(line)

            if region in REGION_WHITELIST:
                region_map[region].append(line)

    for region, lines in region_map.items():
        with open(f"ip_{region}.txt", "w") as f:
            f.writelines(lines)

    print("[*] Done.")

if __name__ == "__main__":
    main()