import subprocess
import random
import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor

# =========================
# ===== 参数区（只改这里）=====
# =========================

CF_CIDRS = [
    "104.16.0.0/12",
    "162.159.0.0/16",
    "172.64.0.0/13"
]

SAMPLE_SIZE = 512          # 抽样 IP 数
TRACE_DOMAIN = "cftrace.yourdomain.com"  # 你的 Worker 域名
TIMEOUT = 4                # curl 超时（秒）
MAX_WORKERS = 25
LATENCY_LIMIT = 800        # 最大可接受延迟 ms

# 端口策略
PORT_MODE = "mixed_random"
HTTPS_PORTS = [443, 8443, 2053, 2083, 2087, 2096]
HTTP_PORTS  = [80, 8080, 8880, 2052, 2082, 2086, 2095]

# cf-ray → 位置映射（可随意增减）
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
    return random.sample(list(net.hosts()), count)

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
        location = COLO_MAP.get(colo, colo)

        return (ip, latency, location)

    except:
        return None

def main():
    print("[*] Sampling IPs...")
    per_cidr = SAMPLE_SIZE // len(CF_CIDRS)
    ips = []
    for cidr in CF_CIDRS:
        ips += random_ips(cidr, per_cidr)

    print(f"[*] Testing {len(ips)} IPs...")
    results = []
    with ThreadPoolExecutor(MAX_WORKERS) as pool:
        for r in pool.map(test_ip, ips):
            if r:
                results.append(r)

    results.sort(key=lambda x: x[1])

    print(f"[*] {len(results)} IPs passed, writing ip.txt")
    with open("ip.txt", "w") as f:
        for ip, latency, location in results:
            port = pick_port()
            f.write(f"{ip}:{port} #{location} {latency}ms\n")

if __name__ == "__main__":
    main()
