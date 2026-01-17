import subprocess
import random
import ipaddress
import time
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

# =========================
# ===== 参数区（只改这里）=====
# =========================

CF_CIDRS = [
    "104.16.0.0/12",
    "162.159.0.0/16",
    "172.64.0.0/13"
]

SAMPLE_SIZE = 512
TRACE_DOMAIN = "sptest.ittool.pp.ua"
TIMEOUT = 4
MAX_WORKERS = 25
LATENCY_LIMIT = 800        # ms
RETRY = 2                 # 每个 IP 测试次数（取最小）

# 端口策略
PORT_MODE = "mixed_random"  # https_fixed / http_fixed / https_random / http_random / mixed_random

HTTPS_PORTS = [443, 8443, 2053, 2083, 2087, 2096]
HTTP_PORTS  = [80, 8080, 8880, 2052, 2082, 2086, 2095]

# cf-ray → 位置映射
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

def pick_port():
    if PORT_MODE == "https_fixed":
        return 443
    if PORT_MODE == "http_fixed":
        return 80
    if PORT_MODE == "https_random":
        return random.choice(HTTPS_PORTS)
    if PORT_MODE == "http_random":
        return random.choice(HTTP_PORTS)
    return random.choice(HTTPS_PORTS + HTTP_PORTS)

def random_ips(cidr, count):
    net = ipaddress.ip_network(cidr)
    base = int(net.network_address)
    max_ip = int(net.broadcast_address)
    return [
        str(ipaddress.ip_address(random.randint(base + 1, max_ip - 1)))
        for _ in range(count)
    ]

def curl_test(ip):
    cmd = [
        "curl", "-sI",
        "--resolve", f"{TRACE_DOMAIN}:443:{ip}",
        f"https://{TRACE_DOMAIN}",
        "--max-time", str(TIMEOUT)
    ]
    start = time.time()
    out = subprocess.check_output(cmd, timeout=TIMEOUT + 1)
    latency = int((time.time() - start) * 1000)
    return out.decode().lower(), latency

def test_ip(ip):
    best_latency = None
    colo = None

    for _ in range(RETRY):
        try:
            headers, latency = curl_test(ip)

            if latency > LATENCY_LIMIT:
                continue

            for line in headers.splitlines():
                if line.startswith("cf-ray"):
                    ray = line.split(":")[1].strip()
                    colo = ray.split("-")[-1].upper()

            if not colo:
                continue

            if best_latency is None or latency < best_latency:
                best_latency = latency

        except:
            continue

    if best_latency is None or not colo:
        return None

    location = COLO_MAP.get(colo, colo)

    return {
        "ip": ip,
        "latency": best_latency,
        "colo": colo,
        "location": location
    }

def main():
    print("[*] Sampling IPs...")

    per_cidr = SAMPLE_SIZE // len(CF_CIDRS)
    ips = []

    for cidr in CF_CIDRS:
        ips.extend(random_ips(cidr, per_cidr))

    print(f"[*] Testing {len(ips)} IPs...")

    results = []

    with ThreadPoolExecutor(MAX_WORKERS) as pool:
        futures = [pool.submit(test_ip, ip) for ip in ips]
        for f in as_completed(futures):
            r = f.result()
            if r:
                results.append(r)

    results.sort(key=lambda x: x["latency"])

    print(f"[*] {len(results)} IPs passed, writing outputs")

    # === 输出 TXT（严格无空格格式）===
    with open("ip.txt", "w") as f:
        for r in results:
            port = pick_port()
            f.write(
                f'{r["ip"]}:{port}#{r["location"]}-{r["latency"]}ms\n'
            )

    # === 输出 JSON（程序友好）===
    with open("ip.json", "w") as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    main()