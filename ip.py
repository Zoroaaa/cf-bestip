# ip_scanner.py
import subprocess
import random
import ipaddress
import requests
import os
import json
import time
import logging
import shutil
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from config import *
from proxy_sources import (
    ProxyInfo,
    fetch_proxifly_proxies,
    fetch_proxydaily_proxies,
    fetch_tomcat1235_proxies,
    fetch_webshare_proxies
)
from tests import check_proxy_with_api, run_internal_tests


# ────────────────────────────────────────────────
# 日志配置
# ────────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format=LOG_FORMAT,
    handlers=[logging.StreamHandler()]
)


# ────────────────────────────────────────────────
# Trace 域名（单 view）
# ────────────────────────────────────────────────
TRACE_DOMAINS = {
    "v0": "sptest.ittool.pp.ua"
}


# ────────────────────────────────────────────────
# 运行环境检查
# ────────────────────────────────────────────────
def check_runtime_dependencies():
    if shutil.which("curl") is None:
        logging.error("❌ 未检测到 curl，可执行文件不存在")
        logging.error("请确认运行环境已安装 curl")
        return False
    return True


# ────────────────────────────────────────────────
# curl 测试
# ────────────────────────────────────────────────
def curl_test_with_proxy(ip, domain, proxy=None):
    try:
        cmd = ["curl", "-k", "-o", "/dev/null", "-s"]

        if proxy:
            if proxy.type in ['socks5', 'socks4']:
                cmd.extend(["--socks5", f"{proxy.host}:{proxy.port}"])
            else:
                cmd.extend(["-x", f"http://{proxy.host}:{proxy.port}"])

        cmd.extend([
            "-w", "%{time_connect} %{time_appconnect} %{http_code}",
            "--http1.1",
            "--connect-timeout", str(CONNECT_TIMEOUT + 2),
            "--max-time", str(TIMEOUT + 3),
            "--resolve", f"{domain}:443:{ip}",
            f"https://{domain}"
        ])

        out = subprocess.check_output(
            cmd,
            timeout=TIMEOUT + 5,
            stderr=subprocess.DEVNULL
        )
        parts = out.decode().strip().split()
        if len(parts) < 3:
            return None

        tc, ta, code = parts
        if code in ["000", "0"]:
            return None

        latency = int((float(tc) + float(ta)) * 1000)
        if latency > LATENCY_LIMIT:
            return None

        hdr_cmd = ["curl", "-k", "-sI"]
        if proxy:
            if proxy.type in ['socks5', 'socks4']:
                hdr_cmd.extend(["--socks5", f"{proxy.host}:{proxy.port}"])
            else:
                hdr_cmd.extend(["-x", f"http://{proxy.host}:{proxy.port}"])

        hdr_cmd.extend([
            "--connect-timeout", str(CONNECT_TIMEOUT + 2),
            "--max-time", str(TIMEOUT + 3),
            "--resolve", f"{domain}:443:{ip}",
            f"https://{domain}"
        ])

        hdr = subprocess.check_output(
            hdr_cmd,
            timeout=TIMEOUT + 3,
            stderr=subprocess.DEVNULL
        ).decode(errors="ignore").lower()

        ray = None
        for line in hdr.splitlines():
            if line.startswith("cf-ray"):
                ray = line.split(":", 1)[1].strip()
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
            "latency": latency,
            "proxy": f"{proxy.host}:{proxy.port}({proxy.type})" if proxy else "direct"
        }

    except subprocess.TimeoutExpired:
        return None
    except Exception as e:
        logging.debug(f"测试失败: {ip} - {e}")
        return None


def test_ip_with_proxy(ip, proxy=None):
    records = []
    for view, domain in TRACE_DOMAINS.items():
        r = curl_test_with_proxy(ip, domain, proxy)
        if r:
            r["view"] = view
            records.append(r)
    return records


# ────────────────────────────────────────────────
# IP 采样（修复内存风险）
# ────────────────────────────────────────────────
def weighted_random_ips(cidrs, total):
    pools = []
    for c in cidrs:
        net = ipaddress.ip_network(c)
        pools.append((net, net.num_addresses))

    total_weight = sum(w for _, w in pools)
    result = []

    for net, weight in pools:
        cnt = max(1, int(total * weight / total_weight))
        for _ in range(cnt):
            offset = random.randint(1, net.num_addresses - 2)
            result.append(net.network_address + offset)

    random.shuffle(result)
    return result[:total]


# ────────────────────────────────────────────────
# 评分
# ────────────────────────────────────────────────
def score_ip(latencies):
    if not latencies:
        return 0

    lat_min = min(latencies)
    lat_max = max(latencies)

    s_consistency = max(0.3, 1 - (lat_max - lat_min) / LATENCY_LIMIT)
    s_latency = 1 / (1 + lat_min / 100)

    return round(s_consistency * s_latency, 4)


def aggregate_nodes(raw):
    ip_map = defaultdict(list)
    for r in raw:
        ip_map[r["ip"]].append(r)

    nodes = []
    for ip, items in ip_map.items():
        latencies = [x["latency"] for x in items]
        score = score_ip(latencies)
        if score <= 0:
            continue

        best = min(items, key=lambda x: x["latency"])
        nodes.append({
            "ip": ip,
            "port": random.choice(HTTPS_PORTS),
            "region": best["region"],
            "colo": best["colo"],
            "latencies": latencies,
            "score": score
        })

    return nodes


# ────────────────────────────────────────────────
# 快速代理真实性验证
# ────────────────────────────────────────────────
def quick_proxy_probe(proxy):
    domain = list(TRACE_DOMAINS.values())[0]
    return curl_test_with_proxy("1.1.1.1", domain, proxy) is not None


# ────────────────────────────────────────────────
# 获取并筛选代理
# ────────────────────────────────────────────────
def get_proxies(region):
    all_proxies = []
    all_proxies.extend(fetch_proxifly_proxies(region, REGION_TO_COUNTRY_CODE))
    all_proxies.extend(fetch_proxydaily_proxies(region, REGION_TO_COUNTRY_CODE, max_pages=2))
    all_proxies.extend(fetch_tomcat1235_proxies(region))
    all_proxies.extend(fetch_webshare_proxies(region))

    if not all_proxies:
        return []

    test_proxies = all_proxies[:50]
    candidates = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_map = {executor.submit(check_proxy_with_api, p): p for p in test_proxies}
        for future in as_completed(future_map):
            proxy = future_map[future]
            try:
                r = future.result()
                if r["success"] and quick_proxy_probe(proxy):
                    candidates.append(proxy)
            except Exception:
                pass

    candidates.sort(key=lambda x: x.tested_latency or 999999)
    return candidates[:MAX_PROXIES_PER_REGION]


# ────────────────────────────────────────────────
# 主入口
# ────────────────────────────────────────────────
def main():
    if not check_runtime_dependencies():
        return

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(DATA_DIR, exist_ok=True)

    logging.info("Cloudflare IP 优选扫描器（Single View Mode）")

    if not run_internal_tests():
        logging.error("内部自检未通过，程序退出")
        return

    cidrs = fetch_cf_ipv4_cidrs()
    if not cidrs:
        logging.error("无法获取 Cloudflare IP 段")
        return

    total_ips = sum(cfg["sample"] for cfg in REGION_CONFIG.values())
    all_ips = weighted_random_ips(cidrs, total_ips)

    offset = 0
    for region, cfg in REGION_CONFIG.items():
        ips = all_ips[offset:offset + cfg["sample"]]
        offset += cfg["sample"]

        proxies = get_proxies(region)
        raw = []

        for ip in ips:
            raw.extend(test_ip_with_proxy(ip, proxies[0] if proxies else None))

        aggregate_nodes(raw)

    logging.info("✅ 扫描完成")


if __name__ == "__main__":
    main()