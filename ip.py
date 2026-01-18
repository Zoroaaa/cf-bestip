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

MAX_OUTPUT_PER_REGION = 32
GOOD_SCORE_THRESHOLD = 0.75
MAX_PROXIES_PER_REGION = 3  # 减少到3个,提高成功率

# 代理测试配置
PROXY_TEST_TIMEOUT = 5  # 代理测试超时(秒)
PROXY_QUICK_TEST_URL = "http://www.gstatic.com/generate_204"  # 用于快速测试
PROXY_MAX_LATENCY = 3000  # 代理最大可接受延迟(毫秒)

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
# 改进的代理获取器
# =========================

class ProxyFetcher:
    """从多个源获取并验证代理"""
    
    def __init__(self, cache_dir=PROXY_CACHE_DIR):
        self.cache_dir = cache_dir
        os.makedirs(cache_dir, exist_ok=True)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def get_cache_path(self, region):
        return os.path.join(self.cache_dir, f"verified_proxies_{region}.json")
    
    def is_cache_valid(self, region, max_age=3600):  # 1小时缓存
        cache_file = self.get_cache_path(region)
        if not os.path.exists(cache_file):
            return False
        age = time.time() - os.path.getmtime(cache_file)
        return age < max_age
    
    def load_from_cache(self, region):
        cache_file = self.get_cache_path(region)
        try:
            with open(cache_file, 'r') as f:
                data = json.load(f)
                logging.info(f"✓ 从缓存加载 {len(data)} 个已验证的 {region} 代理")
                return data
        except:
            return []
    
    def save_to_cache(self, region, proxies):
        if not proxies:
            return
        cache_file = self.get_cache_path(region)
        with open(cache_file, 'w') as f:
            json.dump(proxies, f)
        logging.info(f"✓ 缓存 {len(proxies)} 个已验证代理")
    
    def fetch_from_pubproxy(self, country_code):
        """PubProxy API - 较可靠的免费源"""
        proxies = []
        try:
            url = f"http://pubproxy.com/api/proxy?limit=20&format=json&type=http&country={country_code}"
            resp = self.session.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get('data', []):
                    proxies.append({
                        "host": item['ip'],
                        "port": int(item['port']),
                        "type": item.get('type', 'http'),
                        "country": country_code,
                        "source": "pubproxy"
                    })
        except Exception as e:
            logging.debug(f"PubProxy {country_code} 失败: {e}")
        return proxies
    
    def fetch_from_proxylist_geonode(self, country_code):
        """Geonode - 质量较好"""
        proxies = []
        try:
            url = (
                f"https://proxylist.geonode.com/api/proxy-list"
                f"?limit=50&page=1&sort_by=lastChecked&sort_type=desc"
                f"&country={country_code}"
                f"&protocols=http,https"
                f"&filterUpTime=90"  # 只要90%+在线率
            )
            resp = self.session.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get('data', [])[:30]:
                    proxies.append({
                        "host": item['ip'],
                        "port": int(item['port']),
                        "type": 'http',
                        "country": country_code,
                        "source": "geonode",
                        "uptime": item.get('upTime', 0)
                    })
        except Exception as e:
            logging.debug(f"Geonode {country_code} 失败: {e}")
        return proxies
    
    def fetch_from_proxy11(self):
        """Proxy11 - 备用源"""
        proxies = []
        try:
            url = "https://api.proxy11.com/api/proxy-list?limit=100"
            resp = self.session.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get('proxies', [])[:50]:
                    proxies.append({
                        "host": item['ip'],
                        "port": int(item['port']),
                        "type": 'http',
                        "country": item.get('country', 'UNKNOWN'),
                        "source": "proxy11"
                    })
        except Exception as e:
            logging.debug(f"Proxy11 失败: {e}")
        return proxies
    
    def fetch_from_github_proxy_list(self):
        """GitHub代理列表 - 社区维护"""
        proxies = []
        try:
            # TheSpeedX/PROXY-List
            url = "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt"
            resp = self.session.get(url, timeout=10)
            if resp.status_code == 200:
                for line in resp.text.strip().split('\n')[:100]:
                    if ':' in line:
                        try:
                            host, port = line.strip().split(':')
                            proxies.append({
                                "host": host,
                                "port": int(port),
                                "type": "http",
                                "country": "UNKNOWN",
                                "source": "github"
                            })
                        except:
                            pass
        except Exception as e:
            logging.debug(f"GitHub代理列表失败: {e}")
        return proxies
    
    def fetch_all_sources(self, country_codes):
        """从所有源获取代理"""
        all_proxies = []
        
        # 1. 优先获取指定国家代理
        for country_code in country_codes:
            logging.info(f"  → 获取 {country_code} 代理...")
            
            # 来源1: PubProxy
            proxies = self.fetch_from_pubproxy(country_code)
            all_proxies.extend(proxies)
            time.sleep(0.3)
            
            # 来源2: Geonode
            proxies = self.fetch_from_proxylist_geonode(country_code)
            all_proxies.extend(proxies)
            time.sleep(0.3)
        
        # 2. 通用代理源(作为补充)
        if len(all_proxies) < 20:
            logging.info("  → 获取通用代理...")
            all_proxies.extend(self.fetch_from_proxy11())
            all_proxies.extend(self.fetch_from_github_proxy_list())
        
        # 去重
        unique_proxies = []
        seen = set()
        for p in all_proxies:
            key = f"{p['host']}:{p['port']}"
            if key not in seen:
                seen.add(key)
                unique_proxies.append(p)
        
        logging.info(f"  ✓ 获取到 {len(unique_proxies)} 个不重复代理")
        return unique_proxies
    
    def get_proxies(self, region):
        """获取指定地区的代理"""
        
        # 检查缓存
        if self.is_cache_valid(region):
            cached = self.load_from_cache(region)
            if len(cached) >= 3:
                return cached
        
        country_codes = REGION_CONFIG.get(region, {}).get("codes", [])
        if not country_codes:
            logging.warning(f"未找到 {region} 的国家代码")
            return []
        
        logging.info(f"\n{'='*50}")
        logging.info(f"获取 {region} 地区代理...")
        logging.info(f"{'='*50}")
        
        # 获取原始代理列表
        all_proxies = self.fetch_all_sources(country_codes)
        
        if not all_proxies:
            logging.warning(f"⚠ {region} 未获取到任何代理")
            return []
        
        return all_proxies

# =========================
# 代理快速验证
# =========================

def quick_test_proxy(proxy, test_url=PROXY_QUICK_TEST_URL):
    """快速测试代理连通性"""
    try:
        proxy_url = f"{proxy.get('type', 'http')}://{proxy['host']}:{proxy['port']}"
        proxies_dict = {"http": proxy_url, "https": proxy_url}
        
        start = time.time()
        resp = requests.get(
            test_url,
            proxies=proxies_dict,
            timeout=PROXY_TEST_TIMEOUT,
            allow_redirects=False
        )
        latency = int((time.time() - start) * 1000)
        
        # 204 No Content 或 200 都算成功
        if resp.status_code in [200, 204] and latency < PROXY_MAX_LATENCY:
            proxy['test_latency'] = latency
            return True
    except:
        pass
    return False

def test_proxy_with_cloudflare(proxy):
    """用Cloudflare trace测试代理并获取位置"""
    try:
        proxy_url = f"{proxy.get('type', 'http')}://{proxy['host']}:{proxy['port']}"
        proxies_dict = {"http": proxy_url, "https": proxy_url}
        
        resp = requests.get(
            "https://cloudflare.com/cdn-cgi/trace",
            proxies=proxies_dict,
            timeout=PROXY_TEST_TIMEOUT,
            verify=False
        )
        
        if resp.status_code == 200:
            for line in resp.text.split('\n'):
                if line.startswith('colo='):
                    proxy['colo'] = line.split('=')[1].strip().upper()
                elif line.startswith('loc='):
                    proxy['loc'] = line.split('=')[1].strip().upper()
            return True
    except:
        pass
    return False

def filter_working_proxies(proxies, max_workers=30, max_proxies=MAX_PROXIES_PER_REGION):
    """两阶段筛选代理: 1.快速连通性测试 2.Cloudflare验证"""
    
    if not proxies:
        return []
    
    logging.info(f"\n阶段1: 快速测试 {len(proxies)} 个代理连通性...")
    
    # 阶段1: 快速连通性测试
    quick_pass = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_proxy = {executor.submit(quick_test_proxy, p): p for p in proxies}
        
        for future in as_completed(future_to_proxy):
            proxy = future_to_proxy[future]
            try:
                if future.result(timeout=PROXY_TEST_TIMEOUT + 1):
                    quick_pass.append(proxy)
                    if len(quick_pass) >= max_proxies * 3:  # 多筛选一些备用
                        break
            except:
                pass
    
    # 按延迟排序
    quick_pass.sort(key=lambda x: x.get('test_latency', 9999))
    logging.info(f"  ✓ 通过快速测试: {len(quick_pass)} 个")
    
    if not quick_pass:
        return []
    
    # 阶段2: Cloudflare验证(只测试前面的)
    logging.info(f"\n阶段2: Cloudflare位置验证...")
    working = []
    
    with ThreadPoolExecutor(max_workers=15) as executor:
        future_to_proxy = {
            executor.submit(test_proxy_with_cloudflare, p): p 
            for p in quick_pass[:max_proxies * 2]
        }
        
        for future in as_completed(future_to_proxy):
            if len(working) >= max_proxies:
                break
            
            proxy = future_to_proxy[future]
            try:
                if future.result(timeout=PROXY_TEST_TIMEOUT + 2):
                    working.append(proxy)
                    logging.info(
                        f"  ✓ {proxy['host']}:{proxy['port']} "
                        f"[{proxy.get('colo', 'N/A')}] "
                        f"{proxy.get('test_latency', 0)}ms"
                    )
            except:
                pass
    
    logging.info(f"\n✓ 最终可用: {len(working)} 个代理\n")
    return working

# =========================
# IP测试(通过代理或直连)
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
    """测试单个 IP（多个域名）"""
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
# 分地区扫描(改进策略)
# =========================

def scan_region(region, ips, proxies):
    """扫描指定地区 - 优先代理,降级到直连"""
    logging.info(f"\n{'='*60}")
    logging.info(f"开始扫描地区: {region}")
    logging.info(f"{'='*60}")
    
    raw_results = []
    
    # 策略1: 如果有代理,优先使用代理
    if proxies:
        logging.info(f"使用 {len(proxies)} 个代理进行扫描...")
        
        ips_per_proxy = max(1, len(ips) // len(proxies))
        
        for i, proxy in enumerate(proxies):
            proxy_ips = ips[i*ips_per_proxy:(i+1)*ips_per_proxy]
            
            if not proxy_ips:
                continue
            
            proxy_info = f"{proxy['host']}:{proxy['port']} [{proxy.get('colo', 'N/A')}]"
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
    
    # 策略2: 如果代理结果太少,补充直连扫描
    if len(raw_results) < len(ips) * 0.3:  # 如果结果少于30%
        logging.info(f"⚠ 代理结果不足,使用直连补充扫描...")
        
        # 使用剩余IP或全部IP
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
    logging.info(f"# 策略: 代理优先 → 直连降级")
    logging.info(f"{'#'*60}\n")
    
    # 初始化代理获取器
    proxy_fetcher = ProxyFetcher()
    
    # 获取 Cloudflare IP 段
    logging.info("获取 Cloudflare IP 范围...")
    cidrs = fetch_cf_ipv4_cidrs()
    
    # 生成测试 IP 池
    total_ips = sum(cfg["sample"] for cfg in REGION_CONFIG.values())
    logging.info(f"生成 {total_ips} 个测试 IP...\n")
    all_test_ips = weighted_random_ips(cidrs, total_ips)
    
    # 按地区分配 IP 并扫描
    all_results = []
    region_results = {}
    
    ip_offset = 0
    for region, config in REGION_CONFIG.items():
        sample_size = config["sample"]
        region_ips = all_test_ips[ip_offset:ip_offset + sample_size]
        ip_offset += sample_size
        
        # 获取该地区的代理
        raw_proxies = proxy_fetcher.get_proxies(region)
        
        # 验证代理
        working_proxies = filter_working_proxies(raw_proxies)
        
        # 保存已验证代理到缓存
        if working_proxies:
            proxy_fetcher.save_to_cache(region, working_proxies)
        
        # 扫描
        raw = scan_region(region, region_ips, working_proxies)
        nodes = aggregate_nodes(raw)
        
        region_results[region] = nodes
        all_results.extend(raw)
        
        logging.info(f"{'='*60}")
        logging.info(f"✓ {region}: 发现 {len(nodes)} 个有效节点")
        logging.info(f"{'='*60}\n")
        
        # 避免请求过快
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
