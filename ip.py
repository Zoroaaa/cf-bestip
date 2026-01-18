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

SAMPLE_SIZE = 800
TIMEOUT = 8
CONNECT_TIMEOUT = 4
MAX_WORKERS = 12
LATENCY_LIMIT = 800

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

MAX_OUTPUT_PER_REGION = 16
GOOD_SCORE_THRESHOLD = 0.75
MAX_PROXIES_PER_REGION = 3  # 每个地区从 ProxyIP 域名解析出的 IP 中选前 3 个作为代理

# 代理测试配置
PROXY_TEST_TIMEOUT = 5
PROXY_QUICK_TEST_URL = "http://www.gstatic.com/generate_204"
PROXY_MAX_LATENCY = 3000

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
# 地区对应的 ProxyIP 域名（默认端口 443）
# =========================

REGION_DOMAINS = {
    "HK": ["ProxyIP.HK.CMLiussss.net"],
    "SG": ["ProxyIP.SG.CMLiussss.net"],
    "JP": ["ProxyIP.JP.CMLiussss.net"],
    "KR": ["ProxyIP.KR.CMLiussss.net", "kr.william.us.ci"],
    "TW": ["tw.william.us.ci"],
    "US": ["ProxyIP.US.CMLiussss.net"],
    "DE": ["ProxyIP.DE.CMLiussss.net"],
    "UK": ["ProxyIP.GB.CMLiussss.net"],
    "AU": ["ProxyIP.CMLiussss.net"],  # 全球 fallback
    "CA": ["ProxyIP.CA.CMLiussss.net"],
}

# =========================
# DNS 解析函数
# =========================

def resolve_domain(domain):
    ips = []
    try:
        # IPv4
        resp = requests.get(
            f"https://1.1.1.1/dns-query?name={domain}&type=A",
            headers={"accept": "application/dns-json"},
            timeout=10
        )
        resp.raise_for_status()
        data = resp.json()
        if "Answer" in data:
            ips.extend([ans["data"] for ans in data["Answer"] if ans["type"] == 1])
    except Exception as e:
        logging.debug(f"DNS IPv4 {domain} 失败: {e}")

    try:
        # IPv6
        resp = requests.get(
            f"https://1.1.1.1/dns-query?name={domain}&type=AAAA",
            headers={"accept": "application/dns-json"},
            timeout=10
        )
        resp.raise_for_status()
        data = resp.json()
        if "Answer" in data:
            ips.extend([f"[{ans['data']}]" for ans in data["Answer"] if ans["type"] == 28])
    except Exception as e:
        logging.debug(f"DNS IPv6 {domain} 失败: {e}")

    return ips

# =========================
# ProxyIP 验证 + 延迟测试函数
# =========================

def test_proxy_latency(ip, port=443):
    connect_ip = ip.strip("[]")
    family = socket.AF_INET6 if ':' in connect_ip else socket.AF_INET

    start = time.time()
    try:
        s = socket.socket(family)
        s.settimeout(5)
        s.connect((connect_ip, port))
        s.send(b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: speed.cloudflare.com\r\nConnection: close\r\n\r\n")

        response = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response += chunk
            if len(response) > 2048 or (time.time() - start) > 5:
                break

        response_text = response.decode(errors='ignore').lower()
        s.close()

        if "cf-ray" in response_text and "cloudflare" in response_text and "400 bad request" in response_text:
            latency = int((time.time() - start) * 1000)
            return {"success": True, "latency": latency}
        else:
            return {"success": False, "latency": 999999}
    except Exception as e:
        logging.debug(f"ProxyIP {ip}:{port} 测试失败: {e}")
        return {"success": False, "latency": 999999}

# =========================
# 获取该地区的最佳 ProxyIP 代理（top 3）
# =========================

def get_proxies(region):
    domains = REGION_DOMAINS.get(region, [])
    if not domains:
        logging.warning(f"{region} 无 ProxyIP 域名")
        return []

    all_ips = []
    for domain in domains:
        ips = resolve_domain(domain)
        all_ips.extend(ips)

    all_ips = list(set(all_ips))  # 去重
    logging.info(f"{region} 解析到 {len(all_ips)} 个 IP")

    if not all_ips:
        return []

    # 并行测试有效性和延迟
    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(test_proxy_latency, ip) for ip in all_ips]
        for future, ip in zip(as_completed(futures), all_ips):
            r = future.result()
            if r["success"]:
                results.append({
                    "host": ip.strip("[]"),
                    "port": 443,
                    "type": "http",
                    "test_latency": r["latency"]
                })

    # 按延迟排序，取 top 3
    results.sort(key=lambda x: x["test_latency"])
    best = results[:MAX_PROXIES_PER_REGION]

    logging.info(f"{region} 选出 {len(best)} 个最佳 ProxyIP 代理")
    return best

# =========================
# IP 测试函数（保持原样）
# =========================

def curl_test_with_proxy(ip, domain, proxy=None):
    """使用代理测试 Cloudflare IP"""
    try:
        cmd = ["curl", "-k", "-o", "/dev/null", "-s"]
        
        # 添加代理
        if proxy:
            proxy_type = proxy.get('type', 'http')
            if proxy_type == 'socks5':
                cmd.extend(["--socks5", f"{proxy['host']}:{proxy['port']}"])
            else:
                cmd.extend(["-x", f"{proxy['host']}:{proxy['port']}"])
        
        cmd.extend([
            "-w", "%{time_connect} %{time_appconnect} %{http_code}",
            "--http1.1",
            "--connect-timeout", str(CONNECT_TIMEOUT),
            "--max-time", str(TIMEOUT),
            "--resolve", f"{domain}:443:{ip}",
            f"https://{domain}"
        ])
        
        out = subprocess.check_output(cmd, timeout=TIMEOUT + 2, stderr=subprocess.DEVNULL)
        parts = out.decode().strip().split()
        
        if len(parts) < 3:
            return None
        
        tc, ta, code = parts[0], parts[1], parts[2]
        latency = int((float(tc) + float(ta)) * 1000)
        
        if latency > LATENCY_LIMIT or code in ["000", "0"]:
            return None
        
        # 获取 CF-Ray
        hdr_cmd = ["curl", "-k", "-sI"]
        
        if proxy:
            proxy_type = proxy.get('type', 'http')
            if proxy_type == 'socks5':
                hdr_cmd.extend(["--socks5", f"{proxy['host']}:{proxy['port']}"])
            else:
                hdr_cmd.extend(["-x", f"{proxy['host']}:{proxy['port']}"])
        
        hdr_cmd.extend([
            "--resolve", f"{domain}:443:{ip}",
            f"https://{domain}"
        ])
        
        hdr = subprocess.check_output(
            hdr_cmd,
            timeout=TIMEOUT,
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
            "proxy": f"{proxy['host']}:{proxy['port']}" if proxy else "direct"
        }
    
    except Exception:
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
# 工具函数（保持原样）
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
# 分地区扫描（保持原样）
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
            
            proxy_info = f"{proxy['host']}:{proxy['port']}"
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
    
    if len(raw_results) < len(ips) * 0.3:
        logging.info(f"⚠ 代理结果不足,使用直连补充扫描...")
        
        remaining_ips = ips if not raw_results else ips[:len(ips)//2]
        
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [executor.submit(test_ip_with_proxy, ip, None) for ip in remaining_ips]
            
            for future in as_completed(futures):
                try:
                    batch = future.result(timeout=TIMEOUT + 5)
                    if batch:
                        raw_results.extend(batch)
                except:
                    pass
        
        logging.info(f"  ✓ 直连补充收集: {len(raw_results)} 条总结果")
    
    logging.info(f"✓ {region}: 总计收集 {len(raw_results)} 条测试结果\n")
    return raw_results

# =========================
# 主流程
# =========================

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(DATA_DIR, exist_ok=True)
    
    logging.info(f"\n{'#'*60}")
    logging.info(f"# Cloudflare IP 优选扫描器 (改进版)")
    logging.info(f"# 代理来源: ProxyIP.*.CMLiussss.net 域名解析出的 IP (每个地区选 top 3)")
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
        
        # 获取该地区的 ProxyIP 代理（top 3）
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
    
    # 保存历史
    today = datetime.utcnow().strftime("%Y-%m-%d")
    with open(f"{DATA_DIR}/ip_all_{today}.txt", "w") as f:
        f.writelines(all_lines)
    
    # 清理旧历史
    history_files = sorted([f for f in os.listdir(DATA_DIR) if f.startswith("ip_all_")])
    while len(history_files) > 7:
        os.remove(os.path.join(DATA_DIR, history_files.pop(0)))
    
    # 保存高质量池
    good_pool = [n for n in all_nodes if n["score"] >= GOOD_SCORE_THRESHOLD]
    with open(f"{OUTPUT_DIR}/ip_good_pool.txt", "w") as f:
        for n in good_pool:
            f.write(f'{n["ip"]}:{n["port"]}#{n["region"]}-score{n["score"]}\n')
    
    # 按地区保存（top 16）
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