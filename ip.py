import subprocess
import random
import ipaddress
import requests
import os
import json
import time
import logging
import socket
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from tqdm import tqdm
from bs4 import BeautifulSoup

# =========================
# 配置日志
# =========================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler()]
)

# =========================
# 基础参数
# =========================

CF_IPS_V4_URL = "https://www.cloudflare.com/ips-v4"

TRACE_DOMAINS = {
    "v0": "sptest.ittool.pp.ua",
    "v1": "sptest1.ittool.pp.ua",
    "v2": "sptest2.ittool.pp.ua",
}

SAMPLE_SIZE = 820
TIMEOUT = 6
CONNECT_TIMEOUT = 3
MAX_WORKERS = 32
LATENCY_LIMIT = 500

OUTPUT_DIR = "public"
DATA_DIR = "public/data"
PROXY_CACHE_DIR = "proxy_cache"

HTTPS_PORTS = [443, 8443, 2053, 2083, 2087, 2096]

# 目标地区配置
REGION_CONFIG = {
    "HK": {"codes": ["HK"], "sample": 100},
    "SG": {"codes": ["SG"], "sample": 100},
    "JP": {"codes": ["JP"], "sample": 100},
    "KR": {"codes": ["KR"], "sample": 80},
    "TW": {"codes": ["TW"], "sample": 80},
    "US": {"codes": ["US"], "sample": 120},
    "DE": {"codes": ["DE"], "sample": 60},
    "UK": {"codes": ["GB"], "sample": 60},
    "AU": {"codes": ["AU"], "sample": 60},
    "CA": {"codes": ["CA"], "sample": 60},
}

MAX_OUTPUT_PER_REGION = 8
MAX_PROXIES_PER_REGION = 5  # 每个地区选出最佳的5个代理

# 代理测试配置
PROXY_TEST_TIMEOUT = 5
PROXY_QUICK_TEST_URL = "https://www.cloudflare.com/cdn-cgi/trace"  # 修改为HTTPS测试
PROXY_MAX_LATENCY = 1000
PROXY_LATENCY_PENALTY = 100  # 非SOCKS5代理的延迟惩罚（ms）- 降低惩罚值，给更多机会
SOCKS5_PRIORITY_BOOST = -50  # SOCKS5优先级更高，给予延迟奖励（负值表示减少延迟值）

# 代理来源配置
PROXY_SOURCES = [
    {
        "name": "Proxifly",
        "fetch_func": "fetch_proxifly_proxies",
        "base_url": "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/countries/{}/data.txt",
    },
    {
        "name": "Proxydaily",
        "fetch_func": "fetch_proxydaily_proxies",
        "api_url": "https://proxy-daily.com/api/serverside/proxies",
    },
    {
        "name": "Tomcat1235",
        "fetch_func": "fetch_tomcat1235_proxies",
        "base_url": "https://tomcat1235.nyc.mn/proxy_list?page={}",
    },
]

# 地区代码映射（REGION_CONFIG key -> 代理来源的国家代码）
REGION_TO_COUNTRY_CODE = {
    "HK": "HK",
    "SG": "SG",
    "JP": "JP",
    "KR": "KR",
    "TW": "TW",
    "US": "US",
    "DE": "DE",
    "UK": "GB",
    "AU": "AU",
    "CA": "CA",
}

# 未知地区代理池（全局备用池）
UNKNOWN_REGION_PROXIES = []

# =========================
# IP定位工具（用于代理地区未知时的定位）
# =========================

def locate_ip(ip):
    """使用免费IP定位API获取代理IP的地区代码"""
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = response.json()
        if data['status'] == 'success':
            return data['countryCode'].upper()
        else:
            return None
    except Exception as e:
        logging.debug(f"IP {ip} 定位失败: {e}")
        return None

# =========================
# 从 Proxifly 获取代理列表
# =========================

def fetch_proxifly_proxies(region, source_config):
    """
    从 Proxifly 获取指定地区的代理列表
    返回格式: [{"host": "1.2.3.4", "port": 8080, "type": "http", "source": "Proxifly"}, ...]
    """
    country_code = REGION_TO_COUNTRY_CODE.get(region)
    if not country_code:
        logging.warning(f"{region} 无对应的 Proxifly 国家代码")
        return []

    url = source_config["base_url"].format(country_code)

    try:
        logging.info(f"正在从 Proxifly 获取 {region} 的代理列表...")
        response = requests.get(url, timeout=15)
        response.raise_for_status()

        proxies = []
        lines = response.text.strip().split('\n')

        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            try:
                # 格式: http://IP:PORT 或 socks5://IP:PORT
                if line.startswith('http://'):
                    proxy_type = 'http'
                    line = line.replace('http://', '')
                elif line.startswith('socks5://'):
                    proxy_type = 'socks5'
                    line = line.replace('socks5://', '')
                elif line.startswith('socks4://'):
                    proxy_type = 'socks4'
                    line = line.replace('socks4://', '')
                else:
                    # 没有协议前缀，默认为 http
                    proxy_type = 'http'

                # 解析 IP:PORT
                parts = line.split(':')
                if len(parts) >= 2:
                    host = parts[0].strip()
                    port = int(parts[1].strip())

                    # 验证 IP 格式
                    ipaddress.ip_address(host)

                    proxies.append({
                        "host": host,
                        "port": port,
                        "type": proxy_type,
                        "source": "Proxifly"
                    })
            except (ValueError, ipaddress.AddressValueError, IndexError):
                logging.debug(f"跳过无效代理行: {line}")
                continue

        logging.info(f"✓ {region}: 获取到 {len(proxies)} 个代理 (Proxifly)")
        return proxies

    except requests.RequestException as e:
        logging.error(f"✗ {region}: 获取代理列表失败 (Proxifly) - {e}")
        return []

# =========================
# 从 Proxydaily 获取代理列表
# =========================

def fetch_proxydaily_proxies(region, source_config):
    """
    从 Proxydaily 获取指定地区的代理列表
    返回格式: [{"host": "1.2.3.4", "port": 8080, "type": "http", "source": "Proxydaily"}, ...]
    """
    country_code = REGION_TO_COUNTRY_CODE.get(region)
    if not country_code:
        logging.warning(f"{region} 无对应的 Proxydaily 国家代码")
        return []

    headers = {
        "Accept": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    }
    params = {
        "draw": "1",
        "start": "0",
        "length": "500",  # 最大获取500个
        "search[value]": country_code,  # 按国家过滤
        "_": str(int(time.time() * 1000))
    }

    try:
        logging.info(f"正在从 Proxydaily 获取 {region} 的代理列表...")
        response = requests.get(source_config["api_url"], headers=headers, params=params, timeout=15)
        response.raise_for_status()
        data = response.json()
        proxies = []

        for item in data.get('data', []):
            try:
                protocols = item['protocol'].split(',')
                for proto in protocols:
                    proto = proto.strip().lower()
                    if proto in ['http', 'https', 'socks4', 'socks5']:
                        proxies.append({
                            "host": item['ip'],
                            "port": int(item['port']),
                            "type": proto if proto.startswith('socks') else 'http',
                            "source": "Proxydaily"
                        })
            except:
                continue

        logging.info(f"✓ {region}: 获取到 {len(proxies)} 个代理 (Proxydaily)")
        return proxies

    except requests.RequestException as e:
        logging.error(f"✗ {region}: 获取代理列表失败 (Proxydaily) - {e}")
        return []

# =========================
# 从 Tomcat1235 获取代理列表
# =========================

def fetch_tomcat1235_proxies(region, source_config):
    """
    从 Tomcat1235 获取指定地区的代理列表
    返回格式: [{"host": "1.2.3.4", "port": 8080, "type": "http", "source": "Tomcat1235"}, ...]
    """
    proxies = []
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }

    try:
        logging.info(f"正在从 Tomcat1235 获取 {region} 的代理列表...")
        for page in range(1, 3):  # 只取前2页，避免过多请求
            url = source_config["base_url"].format(page)
            response = requests.get(url, headers=headers, timeout=15)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            table = soup.find('table')
            if not table:
                continue
            rows = table.find_all('tr')[1:]
            for row in rows:
                cells = row.find_all('td')
                if len(cells) < 3:
                    continue
                proto = cells[0].text.strip().lower()
                ip = cells[1].text.strip()
                port = cells[2].text.strip()
                # 国家过滤（Tomcat1235没有直接国家字段，需定位IP）
                country = locate_ip(ip)
                if country != REGION_TO_COUNTRY_CODE.get(region):
                    continue
                if proto in ['http', 'https', 'socks4', 'socks5']:
                    proxies.append({
                        "host": ip,
                        "port": int(port),
                        "type": proto if proto.startswith('socks') else 'http',
                        "source": "Tomcat1235"
                    })

        logging.info(f"✓ {region}: 获取到 {len(proxies)} 个代理 (Tomcat1235)")
        return proxies

    except requests.RequestException as e:
        logging.error(f"✗ {region}: 获取代理列表失败 (Tomcat1235) - {e}")
        return []

# =========================
# 通用代理获取函数（整合多个来源）
# =========================

def fetch_proxies_from_sources(region):
    all_proxies = []
    for source in PROXY_SOURCES:
        fetch_func = globals().get(source["fetch_func"])
        if fetch_func:
            proxies = fetch_func(region, source)
            all_proxies.extend(proxies)

    # 如果没有代理，尝试从全局未知池中获取
    if not all_proxies and UNKNOWN_REGION_PROXIES:
        logging.info(f"{region}: 使用全局未知地区代理池补充")
        all_proxies = random.sample(UNKNOWN_REGION_PROXIES, min(10, len(UNKNOWN_REGION_PROXIES)))

    # 去重
    unique_proxies = {f"{p['host']}:{p['port']}": p for p in all_proxies}.values()
    return list(unique_proxies)

# =========================
# 构建全局未知地区代理池（预先加载）
# =========================

def build_unknown_region_pool():
    global UNKNOWN_REGION_PROXIES
    logging.info("构建全局未知地区代理池...")
    for source in PROXY_SOURCES:
        if source["name"] == "Proxifly":
            # Proxifly有全局文件
            url = "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/all/data.txt"
            try:
                response = requests.get(url, timeout=15)
                lines = response.text.strip().split('\n')
                for line in lines:
                    if not line or line.startswith('#'):
                        continue
                    try:
                        if line.startswith('http://'):
                            proxy_type = 'http'
                            line = line.replace('http://', '')
                        elif line.startswith('socks5://'):
                            proxy_type = 'socks5'
                            line = line.replace('socks5://', '')
                        elif line.startswith('socks4://'):
                            proxy_type = 'socks4'
                            line = line.replace('socks4://', '')
                        else:
                            proxy_type = 'http'
                        parts = line.split(':')
                        host = parts[0].strip()
                        port = int(parts[1].strip())
                        ipaddress.ip_address(host)
                        UNKNOWN_REGION_PROXIES.append({
                            "host": host,
                            "port": port,
                            "type": proxy_type,
                            "source": "Proxifly-Global"
                        })
                    except:
                        continue
            except:
                pass
        # 其他来源类似，可扩展
    logging.info(f"全局未知地区代理池大小: {len(UNKNOWN_REGION_PROXIES)}")

# =========================
# 代理测试函数（仅HTTPS/SOCKS5，SOCKS5优先）
# =========================

def test_proxy_latency(proxy):
    """
    测试代理的连通性和延迟（仅HTTPS测试，SOCKS5优先）
    返回: {"success": True, "latency": 123, "type": "socks5/http"}
    """
    host = proxy["host"]
    port = proxy["port"]
    proxy_type = proxy.get("type", "http")

    start = time.time()

    try:
        # 优先SOCKS5测试
        cmd = ["curl", "-k", "-s", "-o", "/dev/null", "-w", "%{http_code} %{time_total}"]

        if proxy_type in ["socks5", "socks4"]:
            cmd.extend(["--socks5", f"{host}:{port}"])
        else:
            cmd.extend(["-x", f"http://{host}:{port}"])

        cmd.extend([
            "--connect-timeout", str(PROXY_TEST_TIMEOUT),
            "--max-time", str(PROXY_TEST_TIMEOUT),
            "--resolve", "www.cloudflare.com:443:1.1.1.1",  # 示例中类似
            PROXY_QUICK_TEST_URL
        ])

        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=PROXY_TEST_TIMEOUT + 2
        )

        latency = int((time.time() - start) * 1000)

        if result.returncode != 0:
            return {"success": False, "latency": 999999, "type": proxy_type}

        http_code, time_total = result.stdout.decode().strip().split()
        if http_code not in ["200", "204", "301", "302"]:
            return {"success": False, "latency": 999999, "type": proxy_type}

        # SOCKS5优先级更高，给予延迟奖励
        if proxy_type == "socks5":
            latency += SOCKS5_PRIORITY_BOOST  # 负值减少延迟

        # 非SOCKS5惩罚
        elif proxy_type != "socks5":
            latency += PROXY_LATENCY_PENALTY

        return {
            "success": True, 
            "latency": latency,
            "type": proxy_type
        }

    except Exception as e:
        logging.debug(f"代理 {host}:{port} 测试失败: {e}")
        return {"success": False, "latency": 999999, "type": proxy_type}

# =========================
# 获取该地区的最佳代理（top 5）
# =========================

def get_proxies(region):
    """
    获取指定地区的最佳代理（整合多个来源）
    """
    proxies = fetch_proxies_from_sources(region)

    if not proxies:
        logging.warning(f"{region} 无可用代理")
        return []

    # 限制测试数量
    test_proxies = proxies[:50] if len(proxies) > 50 else proxies

    logging.info(f"{region} 测试 {len(test_proxies)} 个代理的HTTPS连通性...")

    candidate_proxies = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_proxy = {executor.submit(test_proxy_latency, p): p for p in test_proxies}

        for future in as_completed(future_to_proxy):
            proxy = future_to_proxy[future]
            try:
                test_result = future.result()
                if test_result["success"] and test_result["latency"] < PROXY_MAX_LATENCY:
                    candidate_proxies.append({
                        "host": proxy["host"],
                        "port": proxy["port"],
                        "type": test_result["type"],
                        "latency": test_result["latency"],
                        "source": proxy["source"]
                    })
            except Exception as e:
                logging.debug(f"代理测试异常: {e}")

    if not candidate_proxies:
        logging.warning(f"⚠ {region} 无可用代理，将完全使用直连")
        return []

    logging.info(f"  ✓ 通过: {len(candidate_proxies)} 个代理")

    # 按 latency 排序（SOCKS5已优先）
    candidate_proxies.sort(key=lambda x: x["latency"])

    # 取 top MAX_PROXIES_PER_REGION
    best_proxies = candidate_proxies[:MAX_PROXIES_PER_REGION]

    logging.info(f"✓ {region} 最终选出 {len(best_proxies)} 个可用代理:")
    for i, p in enumerate(best_proxies, 1):
        logging.info(f"  {i}. {p['host']}:{p['port']} ({p['type']}) - 延迟:{p['latency']}ms ({p['source']})")

    return best_proxies

# =========================
# IP 测试函数（使用代理测试CF IP）
# =========================

def curl_test_with_proxy(ip, domain, proxy=None):
    """使用代理测试 Cloudflare IP"""
    try:
        cmd = ["curl", "-k", "-o", "/dev/null", "-s"]

        # 添加代理
        if proxy:
            proxy_type = proxy.get('type', 'http')
            if proxy_type in ['socks5', 'socks4']:
                cmd.extend(["--socks5", f"{proxy['host']}:{proxy['port']}"])
            else:
                cmd.extend(["-x", f"http://{proxy['host']}:{proxy['port']}"])

        cmd.extend([
            "-w", "%{time_connect} %{time_appconnect} %{http_code}",
            "--http1.1",
            "--connect-timeout", str(CONNECT_TIMEOUT + 2),
            "--max-time", str(TIMEOUT + 3),
            "--resolve", f"{domain}:443:{ip}",
            f"https://{domain}"
        ])

        out = subprocess.check_output(cmd, timeout=TIMEOUT + 5, stderr=subprocess.DEVNULL)
        parts = out.decode().strip().split()

        if len(parts) < 3:
            return None

        tc, ta, code = parts[0], parts[1], parts[2]

        if code in ["000", "0"]:
            return None

        latency = int((float(tc) + float(ta)) * 1000)

        if latency > LATENCY_LIMIT:
            return None

        # 获取 CF-Ray
        hdr_cmd = ["curl", "-k", "-sI"]

        if proxy:
            proxy_type = proxy.get('type', 'http')
            if proxy_type in ['socks5', 'socks4']:
                hdr_cmd.extend(["--socks5", f"{proxy['host']}:{proxy['port']}"])
            else:
                hdr_cmd.extend(["-x", f"http://{proxy['host']}:{proxy['port']}"])

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
                ray = line.split(":")[1].strip()
                break

        if not ray:
            logging.debug(f"IP {ip} 无 CF-Ray")
            return None

        colo = ray.split("-")[-1].upper()
        region = COLO_MAP.get(colo, "UNMAPPED")

        return {
            "ip": str(ip),
            "domain": domain,
            "colo": colo,
            "region": region,
            "latency": latency,
            "proxy": f"{proxy['host']}:{proxy['port']}" if proxy else "direct"
        }

    except subprocess.TimeoutExpired:
        logging.debug(f"测试超时: {ip} via {proxy['host'] if proxy else 'direct'}")
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

def score_ip(latencies):
    if len(latencies) < 2:
        return 0

    lat_min = min(latencies)
    lat_max = max(latencies)

    s_stability = len(latencies) / len(TRACE_DOMAINS)
    s_consistency = max(0.3, 1 - (lat_max - lat_min) / LATENCY_LIMIT)
    s_latency = 1 / (1 + lat_min / 100)

    return round(s_stability * s_consistency * s_latency, 4)

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

# =========================
# 分地区扫描
# =========================

def scan_region(region, ips, proxies):
    logging.info(f"\n{'='*60}")
    logging.info(f"开始扫描地区: {region}")
    logging.info(f"{'='*60}")

    raw_results = []

    if proxies:
        logging.info(f"使用 {len(proxies)} 个代理进行扫描...")

        ips_per_proxy = max(1, len(ips) // len(proxies))

        for i, proxy in enumerate(proxies):
            proxy_ips = ips[i*ips_per_proxy:(i+1)*ips_per_proxy]

            if not proxy_ips:
                continue

            proxy_info = f"{proxy['host']}:{proxy['port']} ({proxy['source']})"
            logging.info(f"  → 通过代理 {proxy_info} 测试 {len(proxy_ips)} 个IP...")

            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = [executor.submit(test_ip_with_proxy, ip, proxy) for ip in proxy_ips]

                for future in as_completed(futures):
                    try:
                        batch = future.result(timeout=TIMEOUT + 5)
                        if batch:
                            raw_results.extend(batch)
                    except:
                        pass

        logging.info(f"  ✓ 代理扫描收集: {len(raw_results)} 条结果")

    expected_results = len(ips) * 0.2

    if len(raw_results) < expected_results:
        supplement_count = len(ips) // 2 if raw_results else len(ips)
        logging.info(f"⚠ 代理结果不足（{len(raw_results)}/{expected_results:.0f}），使用直连补充扫描 {supplement_count} 个IP...")

        remaining_ips = ips[:supplement_count]

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [executor.submit(test_ip_with_proxy, ip, None) for ip in remaining_ips]

            for future in as_completed(futures):
                try:
                    batch = future.result(timeout=TIMEOUT + 5)
                    if batch:
                        raw_results.extend(batch)
                except:
                    pass

        logging.info(f"  ✓ 直连补充收集，当前总计: {len(raw_results)} 条结果")
    else:
        logging.info(f"  ✓ 代理结果充足，跳过直连补充")

    logging.info(f"✓ {region}: 总计收集 {len(raw_results)} 条测试结果\n")
    return raw_results

# =========================
# 主流程
# =========================

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(DATA_DIR, exist_ok=True)

    logging.info(f"\n{'#'*60}")
    logging.info(f"# Cloudflare IP 优选扫描器 (多源版)")
    logging.info(f"# 代理来源: Proxifly, Proxydaily, Tomcat1235")
    logging.info(f"# 每个地区选出延迟最低的 {MAX_PROXIES_PER_REGION} 个代理 (SOCKS5优先)")
    logging.info(f"# 每个地区输出 top {MAX_OUTPUT_PER_REGION} 个优选 IP")
    logging.info(f"{'#'*60}\n")

    # 构建全局未知地区代理池
    build_unknown_region_pool()

    # 获取 Cloudflare IP 段
    logging.info("获取 Cloudflare IP 范围...")
    cidrs = fetch_cf_ipv4_cidrs()

    # 生成测试 IP 池
    total_ips = sum(cfg["sample"] for cfg in REGION_CONFIG.values())
    logging.info(f"生成 {total_ips} 个测试 IP...\n")
    all_test_ips = weighted_random_ips(cidrs, total_ips)

    all_results = []
    region_results = {}

    ip_offset = 0
    for region, config in REGION_CONFIG.items():
        sample_size = config["sample"]
        region_ips = all_test_ips[ip_offset:ip_offset + sample_size]
        ip_offset += sample_size

        # 获取该地区的最佳代理（top 5）
        proxies = get_proxies(region)

        # 扫描
        raw = scan_region(region, region_ips, proxies)
        nodes = aggregate_nodes(raw)

        region_results[region] = nodes
        all_results.extend(raw)

        logging.info(f"{'='*60}")
        logging.info(f"✓ {region}: 发现 {len(nodes)} 个有效节点")
        logging.info(f"{'='*60}\n")

        time.sleep(1)

    # 汇总所有节点
    all_nodes = aggregate_nodes(all_results)
    all_nodes.sort(key=lambda x: x["score"], reverse=True)

    logging.info(f"\n{'='*60}")
    logging.info(f"总计发现 {len(all_nodes)} 个节点")
    logging.info(f"{'='*60}\n")

    # 保存总文件
    all_lines = [f'{n["ip"]}:{n["port"]}#{n["region"]}-score{n["score"]}\n' for n in all_nodes]

    with open(f"{OUTPUT_DIR}/ip_all.txt", "w") as f:
        f.writelines(all_lines)

    # 按地区保存（top 8）
    for region, nodes in region_results.items():
        nodes.sort(key=lambda x: x["score"], reverse=True)
        top_nodes = nodes[:MAX_OUTPUT_PER_REGION]

        with open(f"{OUTPUT_DIR}/ip_{region}.txt", "w") as f:
            for n in top_nodes:
                f.write(f'{n["ip"]}:{n["port"]}#{region}-score{n["score"]}\n')

        logging.info(f"{region}: 保存 {len(top_nodes)} 个节点")

    # 保存 JSON
    with open(f"{OUTPUT_DIR}/ip_candidates.json", "w") as f:
        json.dump({
            "meta": {
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "total_nodes": len(all_nodes),
                "regions": {r: len(nodes) for r, nodes in region_results.items()}
            },
            "nodes": all_nodes[:200]  # 只保存前200个
        }, f, indent=2)

    # 打印统计
    print("\n" + "="*60)
    print("📊 扫描统计")
    print("="*60)
    for region in sorted(region_results.keys()):
        nodes = region_results[region]
        if nodes:
            avg_score = sum(n["score"] for n in nodes) / len(nodes)
            print(f"{region:4s}: {len(nodes):3d} 节点 | 平均分数: {avg_score:.3f}")
    print("="*60)

    logging.info("\n✅ 扫描完成！")

if __name__ == "__main__":
    main()