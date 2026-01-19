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
PROXY_TEST_TIMEOUT = 8  # 增加超时时间，免费代理可能较慢
PROXY_MAX_LATENCY = 2000  # 放宽延迟要求到 2000ms
ALLOW_HTTP_ONLY_PROXY = False  # 严格要求必须支持 HTTPS

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
    "PHX": "US", "DEN": "US", "IAH": "US",
    "FRA": "DE", "MUC": "DE", "AMS": "DE",
    "LHR": "UK", "LGW": "UK", "MAN": "UK",
    "YYZ": "CA", "YVR": "CA",
}

# =========================
# GeoNode 代理列表配置
# =========================
GEONODE_BASE_URL = "https://proxylist.geonode.com/api/proxy-list"

# 地区代码映射
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

# =========================
# 从 GeoNode 获取代理列表（使用 curl + jq）
# =========================

def fetch_geonode_proxies_via_curl(region):
    """
    使用 curl + jq 从 GeoNode 获取 SOCKS5 代理
    返回格式: [{"host": "1.2.3.4", "port": 8080, "type": "socks5"}, ...]
    """
    country_code = REGION_TO_COUNTRY_CODE.get(region)
    if not country_code:
        logging.warning(f"{region} 无对应的 GeoNode 国家代码")
        return []

    # 构建 URL（添加 anonymityLevel=elite 获取高质量代理）
    url = f"{GEONODE_BASE_URL}?limit=500&page=1&sort_by=lastChecked&sort_type=desc&country={country_code}&protocols=socks5&anonymityLevel=elite"

    try:
        logging.info(f"正在从 GeoNode 获取 {region} 的 SOCKS5 代理...")
        
        # 使用 curl + jq 解析
        cmd = [
            "curl", "-s", url,
            "|", "jq", "-r", '.data[] | "\\(.ip):\\(.port)"'
        ]
        
        # 直接使用 shell 执行（因为需要管道）
        result = subprocess.run(
            f'curl -s "{url}" | jq -r \'.data[] | "\\(.ip):\\(.port)"\'',
            shell=True,
            capture_output=True,
            timeout=15
        )

        if result.returncode != 0:
            logging.error(f"✗ {region}: curl/jq 执行失败")
            return []

        proxies = []
        lines = result.stdout.decode().strip().split('\n')

        for line in lines:
            line = line.strip()
            if not line or ':' not in line:
                continue

            try:
                host, port = line.split(':')
                host = host.strip()
                port = int(port.strip())

                # 验证 IP 格式
                ipaddress.ip_address(host)

                proxies.append({
                    "host": host,
                    "port": port,
                    "type": "socks5"
                })

            except (ValueError, ipaddress.AddressValueError) as e:
                logging.debug(f"跳过无效代理: {line} - {e}")
                continue

        logging.info(f"✓ {region}: 获取到 {len(proxies)} 个 SOCKS5 代理")
        return proxies

    except Exception as e:
        logging.error(f"✗ {region}: 获取代理失败 - {e}")
        return []

# =========================
# 代理测试函数（直接测试实际目标域名）
# =========================

def test_proxy_with_target_domain(proxy, test_domain="sptest.ittool.pp.ua"):
    """
    测试代理能否访问目标域名（直接测试 sptest.ittool.pp.ua）
    返回: {"success": True, "latency": 123, "https_ok": True}
    """
    host = proxy["host"]
    port = proxy["port"]
    proxy_type = proxy.get("type", "socks5")

    start = time.time()

    try:
        # 直接测试目标 HTTPS 域名
        cmd = ["curl", "-k", "-s", "-o", "/dev/null", "-w", "%{http_code}"]

        if proxy_type in ["socks5", "socks4"]:
            cmd.extend(["--socks5", f"{host}:{port}"])
        else:
            cmd.extend(["-x", f"http://{host}:{port}"])

        cmd.extend([
            "--connect-timeout", str(PROXY_TEST_TIMEOUT),
            "--max-time", str(PROXY_TEST_TIMEOUT),
            f"https://{test_domain}"
        ])

        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=PROXY_TEST_TIMEOUT + 2
        )

        latency = int((time.time() - start) * 1000)

        if result.returncode != 0:
            return {"success": False, "latency": 999999, "https_ok": False}

        http_code = result.stdout.decode().strip()
        
        # 放宽状态码要求（Cloudflare 可能返回各种状态）
        if http_code in ["000", "0"]:
            return {"success": False, "latency": 999999, "https_ok": False}

        # 只要能连接上就算成功
        https_ok = True

        return {
            "success": True,
            "latency": latency,
            "https_ok": https_ok
        }

    except Exception as e:
        logging.debug(f"代理 {host}:{port} 测试失败: {e}")
        return {"success": False, "latency": 999999, "https_ok": False}

# =========================
# 获取该地区的最佳代理（top 5）
# =========================

def get_proxies(region):
    """
    获取指定地区的最佳 SOCKS5 代理（直接测试目标域名）
    """
    # 使用 curl + jq 获取代理列表
    proxies = fetch_geonode_proxies_via_curl(region)

    if not proxies:
        logging.warning(f"{region} 无可用代理")
        return []

    # 限制测试数量（测试前 50 个最新的）
    test_proxies = proxies[:50]

    logging.info(f"{region} 测试 {len(test_proxies)} 个 SOCKS5 代理访问 sptest.ittool.pp.ua...")

    # 使用第一个测试域名进行测试
    test_domain = list(TRACE_DOMAINS.values())[0]
    
    candidate_proxies = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_proxy = {
            executor.submit(test_proxy_with_target_domain, p, test_domain): p 
            for p in test_proxies
        }

        for future in as_completed(future_to_proxy):
            proxy = future_to_proxy[future]
            try:
                test_result = future.result()
                if test_result["success"] and test_result["latency"] < PROXY_MAX_LATENCY:
                    candidate_proxies.append({
                        "host": proxy["host"],
                        "port": proxy["port"],
                        "type": proxy["type"],
                        "basic_latency": test_result["latency"],
                        "https_ok": test_result["https_ok"]
                    })
                    logging.info(f"  ✓ 可用: {proxy['host']}:{proxy['port']} - 延迟:{test_result['latency']}ms")
            except Exception as e:
                logging.debug(f"代理测试异常: {e}")

    if not candidate_proxies:
        logging.warning(f"⚠ {region} 无可用代理，将完全使用直连")
        return []

    logging.info(f"  ✓ 通过测试: {len(candidate_proxies)} 个代理")

    # 按延迟排序，选出最佳的 5 个
    candidate_proxies.sort(key=lambda x: x["basic_latency"])
    best_proxies = candidate_proxies[:MAX_PROXIES_PER_REGION]

    logging.info(f"✓ {region} 最终选出 {len(best_proxies)} 个可用代理:")
    for i, p in enumerate(best_proxies, 1):
        logging.info(f"  {i}. {p['host']}:{p['port']} (socks5) - 延迟:{p['basic_latency']}ms [HTTPS✓]")

    return best_proxies

# =========================
# IP 测试函数
# =========================

def curl_test_with_proxy(ip, domain, proxy=None):
    """使用代理测试 Cloudflare IP"""
    try:
        cmd = ["curl", "-k", "-o", "/dev/null", "-s"]

        # 添加代理
        if proxy:
            proxy_type = proxy.get('type', 'socks5')
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

        # 放宽条件
        if code in ["000", "0"]:
            return None

        latency = int((float(tc) + float(ta)) * 1000)

        if latency > LATENCY_LIMIT:
            return None

        # 获取 CF-Ray
        hdr_cmd = ["curl", "-k", "-sI"]

        if proxy:
            proxy_type = proxy.get('type', 'socks5')
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
        logging.info(f"使用 {len(proxies)} 个 SOCKS5 代理进行扫描...")

        ips_per_proxy = max(1, len(ips) // len(proxies))

        for i, proxy in enumerate(proxies):
            proxy_ips = ips[i*ips_per_proxy:(i+1)*ips_per_proxy]

            if not proxy_ips:
                continue

            proxy_info = f"{proxy['host']}:{proxy['port']} (socks5)"
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

    # 动态补充
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
    logging.info(f"# Cloudflare IP 优选扫描器 (GeoNode SOCKS5版)")
    logging.info(f"# 代理来源: GeoNode API (SOCKS5 + elite)")
    logging.info(f"# 代理测试: 直接测试 sptest.ittool.pp.ua")
    logging.info(f"# 每个地区选出延迟最低的 {MAX_PROXIES_PER_REGION} 个代理")
    logging.info(f"# 每个地区输出 top {MAX_OUTPUT_PER_REGION} 个优选 IP")
    logging.info(f"{'#'*60}\n")

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

        # 获取该地区的最佳代理
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

    # 按地区保存
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
            "nodes": all_nodes[:200]
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