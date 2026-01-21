# 文件2: ip_scanner.py (修改后版本)
import subprocess
import random
import ipaddress
import requests
import os
import json
import time
import logging
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from proxy_sources import (
    ProxyInfo,
    fetch_proxifly_proxies,
    fetch_proxydaily_proxies,
    fetch_tomcat1235_proxies,
    fetch_hookzof_proxies,
    fetch_proxyscrape_proxies
)

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

SAMPLE_SIZE = 600
TIMEOUT = 15
CONNECT_TIMEOUT = 5
MAX_WORKERS = 20
LATENCY_LIMIT = 1300

OUTPUT_DIR = "public"
DATA_DIR = "public/data"

HTTPS_PORTS = [443, 8443, 2053, 2083, 2087, 2096]

# 代理检测 API 配置
PROXY_CHECK_API_URL = "https://prcheck.ittool.pp.ua/check"  # 填入你的 API 地址,例如: https://your-worker.workers.dev/check
PROXY_CHECK_API_TOKEN = "588wbb"  # 填入你的 API Token

# 目标地区配置
REGION_CONFIG = {
    "HK": {"codes": ["HK"], "sample": 60},
    "SG": {"codes": ["SG"], "sample": 60},
    "JP": {"codes": ["JP"], "sample": 60},
    "KR": {"codes": ["KR"], "sample": 60},
    "TW": {"codes": ["TW"], "sample": 60},
    "US": {"codes": ["US"], "sample": 60},
    "DE": {"codes": ["DE"], "sample": 60},
    "UK": {"codes": ["GB"], "sample": 60},
    "AU": {"codes": ["AU"], "sample": 60},
    "CA": {"codes": ["CA"], "sample": 60},
}

MAX_OUTPUT_PER_REGION = 6
MAX_PROXIES_PER_REGION = 5

# 代理测试配置
PROXY_TEST_TIMEOUT = 10
PROXY_MAX_LATENCY = 1500  # SOCKS5 和 HTTPS 代理的最大延迟
SOCKS5_MAX_LATENCY = 1500  # SOCKS5 专用延迟限制

# =========================
# COLO → Region 映射
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

# 国家代码到地区的映射(用于处理未匹配的代理地区)
COUNTRY_TO_REGION = {
    "HK": "HK", "SG": "SG", "JP": "JP", "KR": "KR", "TW": "TW",
    "US": "US", "DE": "DE", "GB": "UK", "AU": "AU", "CA": "CA",
    "FR": "DE", "NL": "DE", "IT": "DE", "ES": "DE",  # 欧洲其他国家归入DE
    "BR": "US", "MX": "US", "AR": "US",  # 美洲其他国家归入US
    "IN": "SG", "TH": "SG", "ID": "SG", "MY": "SG",  # 亚洲其他国家归入SG
}

# =========================
# 数据源配置
# =========================

REGION_TO_COUNTRY_CODE = {
    "HK": "HK", "SG": "SG", "JP": "JP", "KR": "KR", "TW": "TW",
    "US": "US", "DE": "DE", "UK": "GB", "AU": "AU", "CA": "CA",
}

# =========================
# 使用API检测代理
# =========================

def check_proxy_with_api(proxy_info):
    """使用API检测代理的可用性和信息"""
    if not PROXY_CHECK_API_URL:
        logging.error("未配置 PROXY_CHECK_API_URL,无法检测代理")
        return {"success": False, "latency": 999999}
    
    # 构造代理URL
    if proxy_info.type in ["socks5", "socks4"]:
        proxy_url = f"socks5://{proxy_info.host}:{proxy_info.port}"
    else:
        proxy_url = f"http://{proxy_info.host}:{proxy_info.port}"
    
    start = time.time()
    
    try:
        params = {"proxy": proxy_url}
        if PROXY_CHECK_API_TOKEN:
            params["token"] = PROXY_CHECK_API_TOKEN
        
        response = requests.get(
            PROXY_CHECK_API_URL,
            params=params,
            timeout=PROXY_TEST_TIMEOUT + 2
        )
        
        latency = int((time.time() - start) * 1000)
        
        if response.status_code != 200:
            return {"success": False, "latency": 999999, "https_ok": False}
        
        result = response.json()
        
        if not result.get("success"):
            return {"success": False, "latency": 999999, "https_ok": False}
        
        # 从API结果中提取信息
        location = result.get("location", {})
        country_code = location.get("country_code", "UNKNOWN")
        
        # 更新代理信息
        if proxy_info.country_code == "UNKNOWN":
            proxy_info.country_code = country_code
        
        proxy_info.api_result = result
        
        # 根据代理类型应用延迟限制
        max_latency = SOCKS5_MAX_LATENCY if proxy_info.type == "socks5" else PROXY_MAX_LATENCY
        
        if latency > max_latency:
            return {"success": False, "latency": latency, "https_ok": False}
        
        proxy_info.tested_latency = latency
        proxy_info.https_ok = True
        
        return {
            "success": True,
            "latency": latency,
            "https_ok": True,
            "country_code": country_code
        }
        
    except Exception as e:
        logging.debug(f"代理 {proxy_info.host}:{proxy_info.port} API检测失败: {e}")
        return {"success": False, "latency": 999999, "https_ok": False}

# =========================
# 获取该地区的最佳代理
# =========================

def get_proxies(region):
    """获取指定地区的最佳代理(多数据源聚合)"""
    all_proxies = []
    
    # 数据源 1: Proxifly
    proxifly_proxies = fetch_proxifly_proxies(region, REGION_TO_COUNTRY_CODE)
    all_proxies.extend(proxifly_proxies)
    
    # 数据源 2: ProxyDaily
    proxydaily_proxies = fetch_proxydaily_proxies(region, REGION_TO_COUNTRY_CODE, max_pages=2)
    all_proxies.extend(proxydaily_proxies)
    
    # 数据源 3: Tomcat1235
    tomcat_proxies = fetch_tomcat1235_proxies(region)
    all_proxies.extend(tomcat_proxies)
    
    # 数据源 4: Hookzof
    hookzof_proxies = fetch_hookzof_proxies(region)
    all_proxies.extend(hookzof_proxies)
    
    # 数据源 5: Proxyscrape
    proxyscrape_proxies = fetch_proxyscrape_proxies(region, REGION_TO_COUNTRY_CODE)
    all_proxies.extend(proxyscrape_proxies)
    
    # 地区过滤和映射
    target_country_code = REGION_TO_COUNTRY_CODE.get(region, region.upper())
    filtered_proxies = []
    
    for proxy in all_proxies:
        # 直接匹配
        if proxy.country_code == target_country_code:
            filtered_proxies.append(proxy)
            continue
        
        # 通过映射匹配
        mapped_region = COUNTRY_TO_REGION.get(proxy.country_code)
        if mapped_region == region:
            filtered_proxies.append(proxy)
            continue
    
    if not filtered_proxies:
        logging.warning(f"⚠ {region} 无匹配的代理,尝试使用所有可用代理")
        filtered_proxies = all_proxies
    
    logging.info(f"{region} 共收集 {len(filtered_proxies)} 个代理(来自 {len(all_proxies)} 个原始代理)")
    
    if not filtered_proxies:
        logging.warning(f"⚠ {region} 无可用代理,将完全使用直连")
        return []
    
    # 限制测试数量(优先 SOCKS5)
    socks5_proxies = [p for p in filtered_proxies if p.type == "socks5"]
    https_proxies = [p for p in filtered_proxies if p.type == "https"]
    
    test_proxies = (socks5_proxies[:30] + https_proxies[:30])[:50]
    
    logging.info(f"{region} 测试 {len(test_proxies)} 个代理 (SOCKS5: {len([p for p in test_proxies if p.type == 'socks5'])}, HTTPS: {len([p for p in test_proxies if p.type == 'https'])})")
    
    # 并发测试
    candidate_proxies = []
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_proxy = {executor.submit(check_proxy_with_api, p): p for p in test_proxies}
        
        for future in as_completed(future_to_proxy):
            proxy = future_to_proxy[future]
            try:
                test_result = future.result()
                if test_result["success"]:
                    candidate_proxies.append(proxy)
            except Exception as e:
                logging.debug(f"代理测试异常: {e}")
    
    if not candidate_proxies:
        logging.warning(f"⚠ {region} 无可用代理,将完全使用直连")
        return []
    
    logging.info(f"  ✓ 通过: {len(candidate_proxies)} 个代理")
    
    # 按协议和延迟排序(SOCKS5 优先)
    socks5_list = [p for p in candidate_proxies if p.type == "socks5"]
    https_list = [p for p in candidate_proxies if p.type == "https"]
    
    socks5_list.sort(key=lambda x: x.tested_latency)
    https_list.sort(key=lambda x: x.tested_latency)
    
    # 组合:优先 SOCKS5
    best_proxies = socks5_list[:MAX_PROXIES_PER_REGION]
    remaining = MAX_PROXIES_PER_REGION - len(best_proxies)
    if remaining > 0:
        best_proxies.extend(https_list[:remaining])
    
    logging.info(f"✓ {region} 最终选出 {len(best_proxies)} 个代理:")
    for i, p in enumerate(best_proxies, 1):
        logging.info(f"  {i}. {p.host}:{p.port} ({p.type.upper()}) - 延迟:{p.tested_latency}ms [src:{p.source}]")
    
    return best_proxies

# =========================
# IP 测试函数
# =========================

def curl_test_with_proxy(ip, domain, proxy=None):
    """使用代理测试 Cloudflare IP"""
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
            
            proxy_info = f"{proxy.host}:{proxy.port}({proxy.type})"
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
    
    # 动态补充策略
    expected_results = len(ips) * 0.2
    
    if len(raw_results) < expected_results:
        supplement_count = len(ips) // 2 if raw_results else len(ips)
        logging.info(f"⚠ 代理结果不足({len(raw_results)}/{expected_results:.0f}),使用直连补充 {supplement_count} 个IP...")
        
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
        
        logging.info(f"  ✓ 直连补充收集,当前总计: {len(raw_results)} 条结果")
    else:
        logging.info(f"  ✓ 代理结果充足,跳过直连补充")
    
    logging.info(f"✓ {region}: 总计收集 {len(raw_results)} 条测试结果\n")
    return raw_results

# =========================
# 内部测试函数
# =========================

def run_internal_tests():
    """运行内部可用性测试"""
    logging.info("\n" + "="*60)
    logging.info("开始内部测试...")
    logging.info("="*60)
    
    test_results = {
        "data_sources": {},
        "proxy_tests": {},
        "api_check": None,
        "cf_ip_fetch": None
    }
    
    # 测试 1: Cloudflare IP 段获取
    logging.info("\n[测试 1/5] Cloudflare IP 段获取...")
    try:
        cidrs = fetch_cf_ipv4_cidrs()
        if len(cidrs) > 0:
            logging.info(f"  ✓ 成功获取 {len(cidrs)} 个 IP 段")
            test_results["cf_ip_fetch"] = True
        else:
            logging.error("  ✗ IP 段列表为空")
            test_results["cf_ip_fetch"] = False
    except Exception as e:
        logging.error(f"  ✗ 获取失败: {e}")
        test_results["cf_ip_fetch"] = False
    
    # 测试 2: 数据源测试
    logging.info("\n[测试 2/5] 代理数据源测试...")
    test_region = "US"
    
    # Proxifly
    logging.info("  测试 Proxifly...")
    try:
        proxifly_list = fetch_proxifly_proxies(test_region, REGION_TO_COUNTRY_CODE)
        test_results["data_sources"]["proxifly"] = len(proxifly_list) > 0
        logging.info(f"    ✓ Proxifly: {len(proxifly_list)} 个代理")
    except Exception as e:
        test_results["data_sources"]["proxifly"] = False
        logging.error(f"    ✗ Proxifly 失败: {e}")
    
    # ProxyDaily
    logging.info("  测试 ProxyDaily...")
    try:
        proxydaily_list = fetch_proxydaily_proxies(test_region, REGION_TO_COUNTRY_CODE, max_pages=1)
        test_results["data_sources"]["proxydaily"] = len(proxydaily_list) > 0
        logging.info(f"    ✓ ProxyDaily: {len(proxydaily_list)} 个代理")
    except Exception as e:
        test_results["data_sources"]["proxydaily"] = False
        logging.error(f"    ✗ ProxyDaily 失败: {e}")
    
    # Tomcat1235
    logging.info("  测试 Tomcat1235...")
    try:
        tomcat_list = fetch_tomcat1235_proxies(test_region)
        test_results["data_sources"]["tomcat1235"] = len(tomcat_list) > 0
        logging.info(f"    ✓ Tomcat1235: {len(tomcat_list)} 个代理")
    except Exception as e:
        test_results["data_sources"]["tomcat1235"] = False
        logging.error(f"    ✗ Tomcat1235 失败: {e}")
    
    # Hookzof
    logging.info("  测试 Hookzof...")
    try:
        hookzof_list = fetch_hookzof_proxies(test_region)
        test_results["data_sources"]["hookzof"] = len(hookzof_list) > 0
        logging.info(f"    ✓ Hookzof: {len(hookzof_list)} 个代理")
    except Exception as e:
        test_results["data_sources"]["hookzof"] = False
        logging.error(f"    ✗ Hookzof 失败: {e}")
    
    # Proxyscrape
    logging.info("  测试 Proxyscrape...")
    try:
        proxyscrape_list = fetch_proxyscrape_proxies(test_region, REGION_TO_COUNTRY_CODE)
        test_results["data_sources"]["proxyscrape"] = len(proxyscrape_list) > 0
        logging.info(f"    ✓ Proxyscrape: {len(proxyscrape_list)} 个代理")
    except Exception as e:
        test_results["data_sources"]["proxyscrape"] = False
        logging.error(f"    ✗ Proxyscrape 失败: {e}")
    
    # 测试 3: API 可用性测试
    logging.info("\n[测试 3/5] 代理检测 API 测试...")
    if not PROXY_CHECK_API_URL:
        logging.warning("  ⚠ 未配置 PROXY_CHECK_API_URL,跳过API测试")
        test_results["api_check"] = False
    else:
        try:
            # 使用一个公共代理测试API
            test_proxy = ProxyInfo("8.8.8.8", 1080, "socks5", source="test")
            result = check_proxy_with_api(test_proxy)
            if result.get("success") or "latency" in result:
                logging.info("  ✓ API 响应正常")
                test_results["api_check"] = True
            else:
                logging.warning("  ⚠ API 响应异常")
                test_results["api_check"] = False
        except Exception as e:
            logging.error(f"  ✗ API 测试失败: {e}")
            test_results["api_check"] = False
    
    # 测试 4: 代理连通性测试
    logging.info("\n[测试 4/5] 代理连通性测试...")
    
    # 收集一些测试代理
    all_test_proxies = []
    if test_results["data_sources"].get("proxifly"):
        all_test_proxies.extend(proxifly_list[:3])
    if test_results["data_sources"].get("proxydaily"):
        all_test_proxies.extend(proxydaily_list[:3])
    if test_results["data_sources"].get("hookzof"):
        all_test_proxies.extend(hookzof_list[:3])
    if test_results["data_sources"].get("proxyscrape"):
        all_test_proxies.extend(proxyscrape_list[:3])
    
    if all_test_proxies and PROXY_CHECK_API_URL:
        logging.info(f"  测试 {len(all_test_proxies)} 个代理...")
        working_proxies = 0
        
        for proxy in all_test_proxies[:5]:  # 最多测试5个
            result = check_proxy_with_api(proxy)
            if result["success"]:
                working_proxies += 1
                logging.info(f"    ✓ {proxy.host}:{proxy.port} ({proxy.type}) - {result['latency']}ms")
        
        test_results["proxy_tests"]["working_count"] = working_proxies
        test_results["proxy_tests"]["total_tested"] = len(all_test_proxies[:5])
        
        if working_proxies > 0:
            logging.info(f"  ✓ {working_proxies}/{len(all_test_proxies[:5])} 个代理可用")
        else:
            logging.warning("  ⚠ 没有可用代理")
    else:
        logging.warning("  ⚠ 无代理可测试或API未配置")
        test_results["proxy_tests"]["working_count"] = 0
        test_results["proxy_tests"]["total_tested"] = 0
    
    # 测试 5: CF IP 测试
    logging.info("\n[测试 5/5] Cloudflare IP 测试...")
    try:
        test_ips = weighted_random_ips(cidrs, 5)
        logging.info(f"  测试 {len(test_ips)} 个 Cloudflare IP...")
        
        test_ip = test_ips[0]
        result = curl_test_with_proxy(test_ip, "sptest.ittool.pp.ua", None)
        
        if result:
            logging.info(f"    ✓ 测试成功: {result['ip']} -> {result['region']} ({result['latency']}ms)")
            test_results["cf_ip_test"] = True
        else:
            logging.warning("    ⚠ CF IP 测试未返回结果")
            test_results["cf_ip_test"] = False
    except Exception as e:
        logging.error(f"  ✗ CF IP 测试失败: {e}")
        test_results["cf_ip_test"] = False
    
    # 测试总结
    logging.info("\n" + "="*60)
    logging.info("测试总结")
    logging.info("="*60)
    
    passed_tests = 0
    total_tests = 0
    
    # CF IP 段
    total_tests += 1
    if test_results["cf_ip_fetch"]:
        logging.info("✓ Cloudflare IP 段获取: 通过")
        passed_tests += 1
    else:
        logging.error("✗ Cloudflare IP 段获取: 失败")
    
    # 数据源
    for source, status in test_results["data_sources"].items():
        total_tests += 1
        if status:
            logging.info(f"✓ 数据源 {source}: 通过")
            passed_tests += 1
        else:
            logging.warning(f"⚠ 数据源 {source}: 失败(非致命)")
    
    # API 检测
    total_tests += 1
    if test_results["api_check"]:
        logging.info("✓ 代理检测 API: 通过")
        passed_tests += 1
    else:
        logging.warning("⚠ 代理检测 API: 未配置或失败(非致命)")
    
    # 代理测试
    total_tests += 1
    proxy_working = test_results["proxy_tests"].get("working_count", 0)
    if proxy_working > 0:
        logging.info(f"✓ 代理连通性: 通过 ({proxy_working} 个可用)")
        passed_tests += 1
    else:
        logging.warning("⚠ 代理连通性: 无可用代理(将使用直连)")
    
    # CF IP 测试
    total_tests += 1
    if test_results.get("cf_ip_test"):
        logging.info("✓ CF IP 测试: 通过")
        passed_tests += 1
    else:
        logging.error("✗ CF IP 测试: 失败")
    
    logging.info("="*60)
    logging.info(f"测试结果: {passed_tests}/{total_tests} 通过")
    
    if passed_tests >= total_tests - 2:  # 允许最多2个非关键测试失败
        logging.info("✅ 系统可用性测试通过,可以开始扫描")
        return True
    else:
        logging.error("❌ 系统可用性测试失败,请检查网络和依赖")
        return False

# =========================
# 保存代理列表
# =========================

def save_proxy_list(region_proxies):
    """保存所有可用代理到txt文件"""
    all_proxies_lines = []
    
    for region, proxies in region_proxies.items():
        for proxy in proxies:
            # 格式: ip:port#REGION_延迟_来源代理池
            line = f"{proxy.host}:{proxy.port}#{region}_{proxy.tested_latency}ms_{proxy.source}\n"
            all_proxies_lines.append(line)
    
    # 保存总代理列表
    with open(f"{OUTPUT_DIR}/proxy_all.txt", "w") as f:
        f.writelines(all_proxies_lines)
    
    logging.info(f"✓ 保存代理列表: {len(all_proxies_lines)} 个代理 -> {OUTPUT_DIR}/proxy_all.txt")
    
    # 按地区保存
    for region, proxies in region_proxies.items():
        lines = []
        for proxy in proxies:
            line = f"{proxy.host}:{proxy.port}#{region}_{proxy.tested_latency}ms_{proxy.source}\n"
            lines.append(line)
        
        with open(f"{OUTPUT_DIR}/proxy_{region}.txt", "w") as f:
            f.writelines(lines)
        
        logging.info(f"  {region}: {len(lines)} 个代理")

# =========================
# 加载HTML模板
# =========================

def load_html_template():
    """从独立文件加载HTML模板"""
    template_path = os.path.join(os.path.dirname(__file__), 'template.html')
    with open(template_path, 'r', encoding='utf-8') as f:
        return f.read()

# =========================
# 生成HTML页面
# =========================

def generate_html(all_nodes, region_results, region_proxies):
    """生成HTML展示页面"""
    template = load_html_template()
    
    # 生成地区卡片
    region_cards_html = []
    
    for region in sorted(region_results.keys()):
        nodes = region_results[region]
        if not nodes:
            continue
        
        # 每个地区的IP列表
        ip_items_html = []
        for node in nodes[:MAX_OUTPUT_PER_REGION]:
            min_latency = min(node['latencies'])
            ip_html = f"""
            <div class="ip-item">
                <div class="ip-address">{node['ip']}:{node['port']}</div>
                <div class="ip-meta">
                    <span class="badge badge-score">分数 {node['score']}</span>
                    <span class="badge badge-latency">延迟 {min_latency}ms</span>
                    <span class="badge badge-colo">COLO {node['colo']}</span>
                </div>
            </div>"""
            ip_items_html.append(ip_html)
        
        # 每个地区的代理列表 (新增查阅功能)
        proxy_items_html = []
        proxies = region_proxies.get(region, [])
        for proxy in proxies:
            proxy_html = f"""
            <div class="ip-item proxy-item">
                <div class="ip-address">{proxy.host}:{proxy.port}</div>
                <div class="ip-meta">
                    <span class="badge badge-latency">延迟 {proxy.tested_latency}ms</span>
                    <span class="badge badge-colo">{proxy.type.upper()}</span>
                    <span class="badge badge-score">来源 {proxy.source}</span>
                </div>
            </div>"""
            proxy_items_html.append(proxy_html)
        
        proxy_section = ""
        if proxy_items_html:
            proxy_section = f"""
            <div class="proxy-list">
                <h4>代理列表 ({len(proxies)})</h4>
                {''.join(proxy_items_html)}
            </div>"""
        
        # 地区卡片
        card_html = f"""
        <div class="region-card">
            <div class="region-header">
                <span>{region}</span>
                <span class="region-count">{len(nodes)} 节点</span>
            </div>
            <div class="region-body">
                <div class="ip-list">
                    {''.join(ip_items_html)}
                </div>
                {proxy_section}
                <div class="region-downloads">
                    <a href="ip_{region}.txt" class="region-download-btn btn-primary" download>
                        📥 IP列表
                    </a>
                    <a href="proxy_{region}.txt" class="region-download-btn btn-success" download>
                        🔑 代理列表
                    </a>
                </div>
            </div>
        </div>"""
        region_cards_html.append(card_html)
    
    # 统计信息
    total_proxies = sum(len(proxies) for proxies in region_proxies.values())
    
    # 替换模板变量
    html_content = template.replace('{{GENERATED_TIME}}', datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'))
    html_content = html_content.replace('{{TOTAL_NODES}}', str(len(all_nodes)))
    html_content = html_content.replace('{{TOTAL_REGIONS}}', str(len(region_results)))
    html_content = html_content.replace('{{TOTAL_PROXIES}}', str(total_proxies))
    html_content = html_content.replace('{{REGION_CARDS}}', '\n'.join(region_cards_html))
    
    # 保存HTML文件
    with open(f"{OUTPUT_DIR}/index.html", "w", encoding="utf-8") as f:
        f.write(html_content)
    
    logging.info(f"✓ 生成HTML页面: {OUTPUT_DIR}/index.html")


# =========================
# 主流程
# =========================

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(DATA_DIR, exist_ok=True)
    
    logging.info(f"\n{'#'*60}")
    logging.info(f"# Cloudflare IP 优选扫描器 V2.0 API Edition")
    logging.info(f"# 数据源: Proxifly + ProxyDaily + Tomcat1235 + Hookzof + Proxyscrape")
    logging.info(f"# 支持协议: HTTPS + SOCKS5 (优先)")
    logging.info(f"# 检测方式: API智能检测")
    logging.info(f"# 每地区代理数: {MAX_PROXIES_PER_REGION}")
    logging.info(f"# 每地区输出数: {MAX_OUTPUT_PER_REGION}")
    logging.info(f"{'#'*60}\n")
    
    # 检查API配置
    if not PROXY_CHECK_API_URL:
        logging.warning("⚠ 未配置 PROXY_CHECK_API_URL")
        logging.warning("⚠ 请在脚本开头设置 PROXY_CHECK_API_URL 和 PROXY_CHECK_API_TOKEN")
        logging.warning("⚠ 将继续运行但代理检测功能将不可用\n")
    
    # 运行内部测试
    if not run_internal_tests():
        logging.error("\n❌ 内部测试未通过,程序退出")
        return
    
    logging.info("\n" + "="*60)
    logging.info("开始正式扫描...")
    logging.info("="*60)
    
    # 获取 Cloudflare IP 段
    logging.info("\n获取 Cloudflare IP 范围...")
    cidrs = fetch_cf_ipv4_cidrs()
    
    # 生成测试 IP 池
    total_ips = sum(cfg["sample"] for cfg in REGION_CONFIG.values())
    logging.info(f"生成 {total_ips} 个测试 IP...\n")
    all_test_ips = weighted_random_ips(cidrs, total_ips)
    
    all_results = []
    region_results = {}
    region_proxies = {}  # 存储每个地区的代理
    
    ip_offset = 0
    for region, config in REGION_CONFIG.items():
        sample_size = config["sample"]
        region_ips = all_test_ips[ip_offset:ip_offset + sample_size]
        ip_offset += sample_size
        
        # 获取该地区的最佳代理
        proxies = get_proxies(region)
        region_proxies[region] = proxies  # 保存代理列表
        
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
    
    # 按地区保存IP
    for region, nodes in region_results.items():
        nodes.sort(key=lambda x: x["score"], reverse=True)
        top_nodes = nodes[:MAX_OUTPUT_PER_REGION]
        
        with open(f"{OUTPUT_DIR}/ip_{region}.txt", "w") as f:
            for n in top_nodes:
                f.write(f'{n["ip"]}:{n["port"]}#{region}-score{n["score"]}\n')
        
        logging.info(f"{region}: 保存 {len(top_nodes)} 个节点")
    
    # 保存代理列表
    save_proxy_list(region_proxies)
    
    # 保存 JSON
    with open(f"{OUTPUT_DIR}/ip_candidates.json", "w") as f:
        json.dump({
            "meta": {
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "total_nodes": len(all_nodes),
                "regions": {r: len(nodes) for r, nodes in region_results.items()},
                "version": "2.0-api",
                "data_sources": ["proxifly", "proxydaily", "tomcat1235", "hookzof", "proxyscrape"],
                "protocols": ["https", "socks5"],
                "proxy_check_method": "api",
                "total_proxies": sum(len(proxies) for proxies in region_proxies.values())
            },
            "nodes": all_nodes[:200]
        }, f, indent=2)
    
    # 生成HTML页面
    generate_html(all_nodes, region_results, region_proxies)
    
    # 打印统计
    print("\n" + "="*60)
    print("📊 扫描统计")
    print("="*60)
    for region in sorted(region_results.keys()):
        nodes = region_results[region]
        proxies = region_proxies.get(region, [])
        if nodes:
            avg_score = sum(n["score"] for n in nodes) / len(nodes)
            print(f"{region:4s}: {len(nodes):3d} 节点 | {len(proxies):2d} 代理 | 平均分数: {avg_score:.3f}")
    
    total_proxies = sum(len(p) for p in region_proxies.values())
    print("="*60)
    print(f"总代理数: {total_proxies}")
    print("="*60)
    
    logging.info("\n✅ 扫描完成!")
    logging.info(f"结果已保存到 {OUTPUT_DIR}/ 目录")
    logging.info(f"  - IP列表: ip_all.txt, ip_[REGION].txt")
    logging.info(f"  - 代理列表: proxy_all.txt, proxy_[REGION].txt")
    logging.info(f"  - JSON数据: ip_candidates.json")
    logging.info(f"  - HTML页面: index.html")

if __name__ == "__main__":
    main()