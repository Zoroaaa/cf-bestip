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
    handlers=[
        logging.StreamHandler()
    ]
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

SAMPLE_SIZE = 800  # 减少总数，因为要分配给多个地区
TIMEOUT = 6
CONNECT_TIMEOUT = 3
MAX_WORKERS = 16  # 降低并发，避免代理过载
LATENCY_LIMIT = 800  # 代理会增加延迟，适当放宽

OUTPUT_DIR = "public"
DATA_DIR = "public/data"
PROXY_CACHE_DIR = "proxy_cache"

HTTPS_PORTS = [443, 8443, 2053, 2083, 2087, 2096]

# 目标地区及对应国家代码
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
GOOD_SCORE_THRESHOLD = 0.7  # 降低阈值，因为代理测试分数会偏低
MAX_PROXIES_PER_REGION = 5  # 每个地区最多使用5个代理

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
# 代理获取器
# =========================

class ProxyFetcher:
    """从多个源获取免费代理"""
    
    def __init__(self, cache_dir=PROXY_CACHE_DIR):
        self.cache_dir = cache_dir
        os.makedirs(cache_dir, exist_ok=True)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def get_cache_path(self, region):
        return os.path.join(self.cache_dir, f"proxies_{region}.json")
    
    def is_cache_valid(self, region, max_age=1800):  # 30分钟缓存
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
                logging.info(f"从缓存加载 {len(data)} 个 {region} 代理")
                return data
        except:
            return []
    
    def save_to_cache(self, region, proxies):
        cache_file = self.get_cache_path(region)
        with open(cache_file, 'w') as f:
            json.dump(proxies, f)
        logging.info(f"缓存 {len(proxies)} 个 {region} 代理")
    
    def fetch_from_proxyscrape(self, country_code):
        """ProxyScrape API"""
        proxies = []
        try:
            for protocol in ['http', 'socks5']:
                url = (
                    f"https://api.proxyscrape.com/v2/?request=get"
                    f"&protocol={protocol}"
                    f"&timeout=10000"
                    f"&country={country_code}"
                    f"&ssl=yes"
                    f"&anonymity=elite,anonymous"
                )
                resp = self.session.get(url, timeout=15)
                if resp.status_code == 200:
                    for line in resp.text.strip().split('\n')[:50]:
                        if ':' in line:
                            host, port = line.strip().split(':')
                            proxies.append({
                                "host": host.strip(),
                                "port": int(port.strip()),
                                "type": protocol,
                                "country": country_code,
                                "source": "proxyscrape"
                            })
                time.sleep(1)
        except Exception as e:
            logging.warning(f"ProxyScrape {country_code} 失败: {e}")
        return proxies
    
    def fetch_from_geonode(self, country_code):
        """Geonode API"""
        proxies = []
        try:
            url = (
                f"https://proxylist.geonode.com/api/proxy-list"
                f"?limit=100"
                f"&page=1"
                f"&sort_by=lastChecked"
                f"&sort_type=desc"
                f"&country={country_code}"
                f"&protocols=http,https,socks5"
            )
            resp = self.session.get(url, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get('data', [])[:50]:
                    protocols = item.get('protocols', [])
                    proto = 'socks5' if 'socks5' in protocols else 'http'
                    proxies.append({
                        "host": item['ip'],
                        "port": int(item['port']),
                        "type": proto,
                        "country": country_code,
                        "source": "geonode"
                    })
        except Exception as e:
            logging.warning(f"Geonode {country_code} 失败: {e}")
        return proxies
    
    def fetch_from_proxylist_download(self):
        """通用代理列表"""
        proxies = []
        try:
            url = "https://www.proxy-list.download/api/v1/get?type=https"
            resp = self.session.get(url, timeout=15)
            if resp.status_code == 200:
                for line in resp.text.strip().split('\n')[:100]:
                    if ':' in line:
                        host, port = line.strip().split(':')
                        proxies.append({
                            "host": host.strip(),
                            "port": int(port.strip()),
                            "type": "http",
                            "country": "UNKNOWN",
                            "source": "proxylist"
                        })
        except Exception as e:
            logging.warning(f"Proxy-list 失败: {e}")
        return proxies
    
    def fetch_from_openproxylist(self):
        """OpenProxyList"""
        proxies = []
        try:
            url = "https://api.openproxylist.xyz/http.txt"
            resp = self.session.get(url, timeout=15)
            if resp.status_code == 200:
                for line in resp.text.strip().split('\n')[:100]:
                    if ':' in line:
                        host, port = line.strip().split(':')
                        proxies.append({
                            "host": host.strip(),
                            "port": int(port.strip()),
                            "type": "http",
                            "country": "UNKNOWN",
                            "source": "openproxy"
                        })
        except Exception as e:
            logging.warning(f"OpenProxyList 失败: {e}")
        return proxies
    
    def get_proxies(self, region):
        """获取指定地区的代理"""
        
        # 检查缓存
        if self.is_cache_valid(region):
            cached = self.load_from_cache(region)
            if len(cached) >= 10:
                return cached
        
        country_codes = REGION_CONFIG.get(region, {}).get("codes", [])
        if not country_codes:
            logging.warning(f"未找到 {region} 的国家代码配置")
            return []
        
        all_proxies = []
        
        # 从多个源获取
        for country_code in country_codes:
            logging.info(f"正在获取 {region} ({country_code}) 的代理...")
            
            # 来源1: ProxyScrape
            proxies = self.fetch_from_proxyscrape(country_code)
            all_proxies.extend(proxies)
            time.sleep(0.5)
            
            # 来源2: Geonode
            proxies = self.fetch_from_geonode(country_code)
            all_proxies.extend(proxies)
            time.sleep(0.5)
        
        # 来源3: 通用代理（作为补充）
        if len(all_proxies) < 20:
            proxies = self.fetch_from_proxylist_download()
            all_proxies.extend(proxies)
            
            proxies = self.fetch_from_openproxylist()
            all_proxies.extend(proxies)
        
        # 去重
        unique_proxies = []
        seen = set()
        for p in all_proxies:
            key = f"{p['host']}:{p['port']}"
            if key not in seen:
                seen.add(key)
                unique_proxies.append(p)
        
        # 保存缓存
        if unique_proxies:
            self.save_to_cache(region, unique_proxies)
        
        logging.info(f"获取到 {len(unique_proxies)} 个 {region} 代理")
        return unique_proxies

# =========================
# 代理测试和筛选
# =========================

def test_proxy(proxy, test_url="https://cloudflare.com/cdn-cgi/trace", timeout=8):
    """测试代理可用性"""
    try:
        proxy_url = f"{proxy['type']}://{proxy['host']}:{proxy['port']}"
        proxies_dict = {
            "http": proxy_url,
            "https": proxy_url
        }
        
        start = time.time()
        resp = requests.get(
            test_url,
            proxies=proxies_dict,
            timeout=timeout,
            verify=False  # 免费代理可能证书问题
        )
        latency = int((time.time() - start) * 1000)
        
        if resp.status_code == 200:
            # 解析位置信息
            for line in resp.text.split('\n'):
                if line.startswith('colo='):
                    proxy['colo'] = line.split('=')[1].strip().upper()
                elif line.startswith('loc='):
                    proxy['loc'] = line.split('=')[1].strip().upper()
            
            proxy['test_latency'] = latency
            return True
        
    except Exception as e:
        pass
    
    return False

def filter_working_proxies(proxies, max_workers=20, max_proxies=5):
    """并发筛选可用代理"""
    working = []
    
    logging.info(f"开始测试 {len(proxies)} 个代理...")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_proxy = {executor.submit(test_proxy, p): p for p in proxies[:50]}  # 只测试前50个
        
        for future in as_completed(future_to_proxy):
            if len(working) >= max_proxies:
                break
            
            proxy = future_to_proxy[future]
            try:
                if future.result(timeout=10):
                    working.append(proxy)
                    logging.info(f"✓ 可用代理: {proxy['host']}:{proxy['port']} "
                               f"[{proxy.get('colo', 'N/A')}] "
                               f"延迟:{proxy.get('test_latency', 0)}ms")
            except:
                pass
    
    logging.info(f"筛选出 {len(working)} 个可用代理")
    return working

# =========================
# 通过代理测试 Cloudflare IP
# =========================

def curl_test_with_proxy(ip, domain, proxy=None):
    """使用代理测试 Cloudflare IP"""
    try:
        cmd = ["curl", "-k"]  # -k 忽略证书验证
        
        # 添加代理
        if proxy:
            if proxy['type'] == 'socks5':
                cmd.extend(["--socks5", f"{proxy['host']}:{proxy['port']}"])
            else:
                cmd.extend(["-x", f"{proxy['host']}:{proxy['port']}"])
        
        cmd.extend([
            "-o", "/dev/null",
            "-s",
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
        
        if latency > LATENCY_LIMIT or code == "000" or code == "0":
            return None
        
        # 获取 CF-Ray
        hdr_cmd = ["curl", "-k", "-sI"]
        
        if proxy:
            if proxy['type'] == 'socks5':
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
    
    except Exception as e:
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
# 分地区扫描
# =========================

def scan_region(region, ips, proxies):
    """扫描指定地区"""
    logging.info(f"\n{'='*60}")
    logging.info(f"开始扫描地区: {region}")
    logging.info(f"{'='*60}")
    
    if not proxies:
        logging.warning(f"{region} 无可用代理，使用直连")
        proxies = [None]
    
    raw_results = []
    ips_per_proxy = max(1, len(ips) // len(proxies))
    
    # 分配 IP 给不同代理
    for i, proxy in enumerate(proxies):
        proxy_ips = ips[i*ips_per_proxy:(i+1)*ips_per_proxy]
        
        if not proxy_ips:
            continue
        
        proxy_info = f"{proxy['host']}:{proxy['port']}" if proxy else "直连"
        logging.info(f"通过 {proxy_info} 测试 {len(proxy_ips)} 个 IP...")
        
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [executor.submit(test_ip_with_proxy, ip, proxy) for ip in proxy_ips]
            
            for future in as_completed(futures):
                try:
                    batch = future.result(timeout=TIMEOUT + 5)
                    if batch:
                        raw_results.extend(batch)
                except:
                    pass
    
    logging.info(f"{region}: 收集到 {len(raw_results)} 条测试结果")
    return raw_results

# =========================
# 主流程
# =========================

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(DATA_DIR, exist_ok=True)
    
    # 初始化代理获取器
    proxy_fetcher = ProxyFetcher()
    
    # 获取 Cloudflare IP 段
    logging.info("获取 Cloudflare IP 范围...")
    cidrs = fetch_cf_ipv4_cidrs()
    
    # 生成测试 IP 池
    total_ips = sum(cfg["sample"] for cfg in REGION_CONFIG.values())
    logging.info(f"生成 {total_ips} 个测试 IP...")
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
        logging.info(f"\n获取 {region} 地区的代理...")
        proxies = proxy_fetcher.get_proxies(region)
        
        # 筛选可用代理
        working_proxies = filter_working_proxies(proxies, max_proxies=MAX_PROXIES_PER_REGION)
        
        # 扫描
        raw = scan_region(region, region_ips, working_proxies)
        nodes = aggregate_nodes(raw)
        
        region_results[region] = nodes
        all_results.extend(raw)
        
        logging.info(f"✓ {region}: 发现 {len(nodes)} 个有效节点")
        
        # 避免请求过快
        time.sleep(2)
    
    # 汇总所有节点
    all_nodes = aggregate_nodes(all_results)
    all_nodes.sort(key=lambda x: x["score"], reverse=True)
    
    logging.info(f"\n总计发现 {len(all_nodes)} 个节点")
    
    # 保存总文件
    all_lines = [f'{n["ip"]}:{n["port"]}#{n["region"]}-score{n["score"]}\n' for n in all_nodes]
    
    with open(f"{OUTPUT_DIR}/ip_all.txt", "w") as f:
        f.writelines(all_lines)
    
    # 保存历史
    os.makedirs(DATA_DIR, exist_ok=True)
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
    
    logging.info("\n✅ 扫描完成！")
    
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

if __name__ == "__main__":
    main()
