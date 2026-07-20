# ip_scanner.py
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
from datetime import datetime, timezone

from config import *
from proxy_sources import (
    ProxyInfo,
    fetch_proxifly_proxies,
    fetch_proxydaily_proxies,
    fetch_tomcat1235_proxies,
    fetch_monosans_socks5_proxies
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


def curl_test(ip, proxy=None):
    """单域名测试连通性 + 延迟 + colo"""
    try:
        cmd = ["curl", "-k", "-o", "/dev/null", "-s"]

        if proxy:
            # ⚠️ 优化：使用 get_proxy_url() 方法简化代码
            if proxy.type in ['socks5', 'socks4']:
                # SOCKS5 代理
                if proxy.api_result and proxy.api_result.get("username"):
                    username = proxy.api_result["username"]
                    password = proxy.api_result["password"]
                    proxy_url = f"{username}:{password}@{proxy.host}:{proxy.port}"
                else:
                    proxy_url = f"{proxy.host}:{proxy.port}"
                cmd.extend(["--socks5", proxy_url])
            else:
                # HTTPS/HTTP 代理 - 使用新方法
                proxy_url = proxy.get_proxy_url("http")
                cmd.extend(["-x", proxy_url])

        cmd.extend([
            "-w", "%{time_connect} %{time_appconnect} %{http_code}",
            "--http1.1",
            "--connect-timeout", str(CONNECT_TIMEOUT + 2),
            "--max-time", str(TIMEOUT + 3),
            "--resolve", f"{TRACE_DOMAIN}:443:{ip}",
            f"https://{TRACE_DOMAIN}"
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

        # 获取 CF-Ray → colo
        hdr_cmd = ["curl", "-k", "-sI"]

        if proxy:
            # ⚠️ 优化：同样使用 get_proxy_url() 方法
            if proxy.type in ['socks5', 'socks4']:
                if proxy.api_result and proxy.api_result.get("username"):
                    username = proxy.api_result["username"]
                    password = proxy.api_result["password"]
                    proxy_url = f"{username}:{password}@{proxy.host}:{proxy.port}"
                else:
                    proxy_url = f"{proxy.host}:{proxy.port}"
                hdr_cmd.extend(["--socks5", proxy_url])
            else:
                proxy_url = proxy.get_proxy_url("http")
                hdr_cmd.extend(["-x", proxy_url])

        hdr_cmd.extend([
            "--connect-timeout", str(CONNECT_TIMEOUT + 2),
            "--max-time", str(TIMEOUT + 3),
            "--resolve", f"{TRACE_DOMAIN}:443:{ip}",
            f"https://{TRACE_DOMAIN}"
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
            "domain": TRACE_DOMAIN,
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


def test_ip(ip, proxy=None):
    """现在只测一个域名"""
    result = curl_test(ip, proxy)
    if result:
        return [result]
    return []


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
    """单域名后 latencies 长度最多为1"""
    if not latencies:
        return 0

    lat = latencies[0]
    score = 1 / (1 + lat / 200)
    score = round(score, 4)
    return score


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


def scan_region(region, ips, proxies):
    logging.info(f"\n{'='*60}")
    logging.info(f"开始扫描地区: {region}")
    logging.info(f"{'='*60}")

    raw_results = []
    MIN_EXPECTED_NODES = 8

    if proxies:
        logging.info(f"使用 {len(proxies)} 个代理进行扫描...")
        ips_per_proxy = max(1, len(ips) // len(proxies))

        for i, proxy in enumerate(proxies):
            proxy_ips = ips[i*ips_per_proxy:(i+1)*ips_per_proxy]
            if not proxy_ips:
                continue

            # ⚠️ 修改：显示代理信息时标注是否需要认证
            auth_info = ""
            if proxy.api_result and proxy.api_result.get("username"):
                auth_info = "[AUTH]"
            proxy_info = f"{proxy.host}:{proxy.port}({proxy.type}){auth_info}"
            logging.info(f"  → 通过代理 {proxy_info} 测试 {len(proxy_ips)} 个IP...")

            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = [executor.submit(test_ip, ip, proxy) for ip in proxy_ips]

                for future in as_completed(futures):
                    try:
                        batch = future.result(timeout=TIMEOUT + 5)
                        raw_results.extend(batch)
                    except:
                        pass

        logging.info(f"  ✓ 代理扫描收集: {len(raw_results)} 条结果")

    current_nodes = len(aggregate_nodes(raw_results))
    
    if current_nodes < MIN_EXPECTED_NODES:
        needed_nodes = MIN_EXPECTED_NODES - current_nodes
        supplement_count = min(len(ips) // 2, needed_nodes * 5)
        
        logging.info(f"⚠ 当前有效节点 {current_nodes} 个,目标 {MIN_EXPECTED_NODES} 个")
        logging.info(f"  使用直连补充测试 {supplement_count} 个IP...")

        remaining_ips = ips[:supplement_count]

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [executor.submit(test_ip, ip, None) for ip in remaining_ips]

            for future in as_completed(futures):
                try:
                    batch = future.result(timeout=TIMEOUT + 5)
                    raw_results.extend(batch)
                except:
                    pass

        final_nodes = len(aggregate_nodes(raw_results))
        logging.info(f"  ✓ 直连补充后有效节点: {final_nodes} 个")
    else:
        logging.info(f"  ✓ 代理结果充足 ({current_nodes} 个节点),跳过直连补充")

    logging.info(f"✓ {region}: 总计收集 {len(raw_results)} 条测试结果\n")
    return raw_results


def calculate_test_count(available_count, target_count):
    threshold_low = target_count * 5
    threshold_high = target_count * 25
    max_test = target_count * 10
    
    if available_count <= threshold_low:
        test_count = available_count
        logging.debug(f"  代理数量 {available_count} <= {threshold_low},全部测试")
    elif available_count < threshold_high:
        test_count = threshold_low
        logging.debug(f"  代理数量 {available_count} 在5-25倍区间,随机抽取 {test_count} 条测试")
    else:
        test_count = min(available_count // 5, max_test)
        logging.debug(f"  代理数量 {available_count} >= {threshold_high},测试 1/5 = {test_count} 条(上限 {max_test})")
    
    return max(test_count, target_count)


def get_proxies(region):
    all_proxies = []

    all_proxies.extend(fetch_proxifly_proxies(region, REGION_TO_COUNTRY_CODE))
    all_proxies.extend(fetch_proxydaily_proxies(region, REGION_TO_COUNTRY_CODE))
    all_proxies.extend(fetch_tomcat1235_proxies(region))
    all_proxies.extend(fetch_monosans_socks5_proxies(region))

    if not all_proxies:
        logging.warning(f"⚠ {region} 未获取到任何代理")
        return []

    target_country_code = REGION_TO_COUNTRY_CODE.get(region, region.upper())
    
    unknown_proxies = [p for p in all_proxies if p.country_code == "UNKNOWN"]
    if unknown_proxies:
        logging.info(f"{region} 发现 {len(unknown_proxies)} 个未知国家码代理,进行API检测...")
        
        test_count = min(5, len(unknown_proxies))
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_proxy = {
                executor.submit(check_proxy_with_api, p): p 
                for p in unknown_proxies[:test_count]
            }
            
            for future in as_completed(future_to_proxy):
                proxy = future_to_proxy[future]
                try:
                    result = future.result(timeout=PROXY_TEST_TIMEOUT + 2)
                    if result["success"] and result.get("country_code"):
                        proxy.country_code = result["country_code"]
                        logging.debug(f"  更新代理国家码: {proxy.host}:{proxy.port} → {proxy.country_code}")
                except Exception as e:
                    logging.debug(f"  代理国家码检测失败: {proxy.host}:{proxy.port} - {e}")
    
    filtered_proxies = []
    for proxy in all_proxies:
        if proxy.country_code == target_country_code:
            filtered_proxies.append(proxy)
            continue
        mapped_region = COUNTRY_TO_REGION.get(proxy.country_code)
        if mapped_region == region:
            filtered_proxies.append(proxy)

    if not filtered_proxies:
        logging.warning(f"⚠ {region} 无精确匹配代理,尝试使用相近地区代理")
        
        region_groups = {
            "US": ["CA"],
            "CA": ["US"],
            "HK": ["SG", "JP"],
            "SG": ["HK", "JP"],
            "JP": ["HK", "SG"],
            "DE": ["FR", "NL", "GB"],
            "FR": ["DE", "NL", "GB"],
            "NL": ["DE", "FR", "GB"],
            "GB": ["DE", "FR", "NL"],
            "IT": ["FR", "DE"],
            "RU": ["DE"],
            "IN": ["SG"],
        }
        
        nearby_regions = region_groups.get(region, [])
        for proxy in all_proxies:
            if proxy.country_code in [REGION_TO_COUNTRY_CODE.get(r) for r in nearby_regions]:
                filtered_proxies.append(proxy)
        
        if not filtered_proxies:
            logging.warning(f"⚠ {region} 无相近地区代理,使用全部代理")
            filtered_proxies = all_proxies

    logging.info(f"{region} 筛选后代理数: {len(filtered_proxies)}")

    if not filtered_proxies:
        return []

    socks5_proxies = [p for p in filtered_proxies if p.type == "socks5"]
    https_proxies = [p for p in filtered_proxies if p.type == "https"]

    available_count = len(socks5_proxies) + len(https_proxies)
    test_count = calculate_test_count(available_count, MAX_PROXIES_PER_REGION)
    
    socks5_ratio = len(socks5_proxies) / available_count if available_count > 0 else 0
    socks5_test_count = int(test_count * socks5_ratio)
    https_test_count = test_count - socks5_test_count
    
    test_proxies = (
        socks5_proxies[:socks5_test_count] + 
        https_proxies[:https_test_count]
    )

    logging.info(f"{region} 将测试 {len(test_proxies)} 个代理 (从 {available_count} 个中选择)")
    logging.info(f"  └─ SOCKS5: {min(socks5_test_count, len(socks5_proxies))} 个, HTTPS: {min(https_test_count, len(https_proxies))} 个")

    candidate_proxies = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_proxy = {executor.submit(check_proxy_with_api, p): p for p in test_proxies}
        for future in as_completed(future_to_proxy):
            proxy = future_to_proxy[future]
            try:
                test_result = future.result()
                if test_result["success"]:
                    candidate_proxies.append(proxy)
            except Exception:
                pass

    if not candidate_proxies:
        logging.warning(f"⚠ {region} 无可用代理通过测试")
        return []

    socks5_list = [p for p in candidate_proxies if p.type == "socks5"]
    https_list = [p for p in candidate_proxies if p.type == "https"]

    socks5_list.sort(key=lambda x: x.tested_latency or 999999)
    https_list.sort(key=lambda x: x.tested_latency or 999999)

    best_proxies = socks5_list[:MAX_PROXIES_PER_REGION]
    remaining = MAX_PROXIES_PER_REGION - len(best_proxies)
    if remaining > 0:
        best_proxies.extend(https_list[:remaining])

    # ⚠️ 修改：显示代理时标注认证信息
    logging.info(f"✓ {region} 最终选出 {len(best_proxies)} 个代理:")
    for i, p in enumerate(best_proxies, 1):
        auth_marker = "[AUTH]" if (p.api_result and p.api_result.get("username")) else ""
        logging.info(f"  {i}. {p.host}:{p.port} ({p.type.upper()}){auth_marker} - 延迟:{p.tested_latency or 'N/A'}ms [src:{p.source}, country:{p.country_code}]")

    return best_proxies


def save_proxy_list(region_proxies):
    all_proxies_lines = []

    for region, proxies in region_proxies.items():
        for proxy in proxies:
            # ⚠️ 修改：如果有认证信息，保存完整格式
            if proxy.api_result and proxy.api_result.get("username"):
                username = proxy.api_result["username"]
                password = proxy.api_result["password"]
                line = f"{username}:{password}@{proxy.host}:{proxy.port}#{region}_{proxy.tested_latency or 'N/A'}ms_{proxy.source}\n"
            else:
                line = f"{proxy.host}:{proxy.port}#{region}_{proxy.tested_latency or 'N/A'}ms_{proxy.source}\n"
            all_proxies_lines.append(line)

    with open(f"{OUTPUT_DIR}/proxy_all.txt", "w", encoding="utf-8") as f:
        f.writelines(all_proxies_lines)

    logging.info(f"✓ 保存总代理列表: {len(all_proxies_lines)} 条 → proxy_all.txt")

    for region, proxies in region_proxies.items():
        lines = []
        for proxy in proxies:
            # ⚠️ 修改：同样处理认证信息
            if proxy.api_result and proxy.api_result.get("username"):
                username = proxy.api_result["username"]
                password = proxy.api_result["password"]
                line = f"{username}:{password}@{proxy.host}:{proxy.port}#{region}_{proxy.tested_latency or 'N/A'}ms_{proxy.source}\n"
            else:
                line = f"{proxy.host}:{proxy.port}#{region}_{proxy.tested_latency or 'N/A'}ms_{proxy.source}\n"
            lines.append(line)

        with open(f"{OUTPUT_DIR}/proxy_{region}.txt", "w", encoding="utf-8") as f:
            f.writelines(lines)

        logging.info(f"  {region}: 保存 {len(lines)} 条代理")


def load_html_template():
    template_path = os.path.join(os.path.dirname(__file__), 'template.html')
    try:
        with open(template_path, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        logging.error("未找到 template.html 文件,跳过 HTML 生成")
        return None


def generate_html(all_nodes, region_results, region_proxies):
    """生成HTML页面"""
    template = load_html_template()
    if not template:
        return

    region_cards_html = []

    for region in sorted(region_results.keys()):
        nodes = region_results[region]
        if not nodes:
            continue

        region_name = REGION_CONFIG.get(region, {}).get("name", region)
        region_flag = REGION_CONFIG.get(region, {}).get("flag", "")

        ip_items_html = []
        for node in nodes[:MAX_OUTPUT_PER_REGION]:
            min_latency = min(node['latencies']) if node['latencies'] else "N/A"
            ip_html = f"""
            <div class="ip-item">
                <div class="ip-address">{node['ip']}:{node['port']}</div>
                <div class="ip-meta">
                    <span class="badge badge-score">分数 {node['score']:.4f}</span>
                    <span class="badge badge-latency">延迟 {min_latency}ms</span>
                    <span class="badge badge-colo">COLO {node['colo']}</span>
                </div>
            </div>"""
            ip_items_html.append(ip_html)

        proxy_items_html = []
        proxies = region_proxies.get(region, [])
        for proxy in proxies:
            # ⚠️ 修改：在HTML中显示是否需要认证
            auth_badge = ""
            if proxy.api_result and proxy.api_result.get("username"):
                auth_badge = '<span class="badge badge-warning">🔐需认证</span>'
            
            proxy_html = f"""
            <div class="proxy-item">
                <div class="ip-address">{proxy.host}:{proxy.port}</div>
                <div class="ip-meta">
                    <span class="badge badge-type">{proxy.type.upper()}</span>
                    <span class="badge badge-latency">{proxy.tested_latency or 'N/A'}ms</span>
                    <span class="badge badge-source">{proxy.source}</span>
                    <span class="badge badge-colo">{proxy.country_code}</span>
                    {auth_badge}
                </div>
            </div>"""
            proxy_items_html.append(proxy_html)

        proxy_section = ""
        if proxy_items_html:
            proxy_section = f"""
            <div class="section-title">🔑 推荐代理 ({len(proxies)})</div>
            <div class="proxy-list">
                {''.join(proxy_items_html)}
            </div>"""

        card_html = f"""
        <div class="region-card">
            <div class="region-header">
                <span>{region_flag} {region_name} ({region})</span>
                <span class="region-count">{len(nodes)} 节点</span>
            </div>
            <div class="region-body">
                <div class="section-title">📡 优选IP ({len(nodes[:MAX_OUTPUT_PER_REGION])})</div>
                <div class="ip-list">
                    {''.join(ip_items_html)}
                </div>
                {proxy_section}
                <div class="region-downloads">
                    <a href="ip_{region}.txt" class="region-download-btn btn-primary" download>📥 下载IP</a>
                    <a href="proxy_{region}.txt" class="region-download-btn btn-success" download>🔑 下载代理</a>
                </div>
            </div>
        </div>"""
        region_cards_html.append(card_html)

    total_proxies = sum(len(proxies) for proxies in region_proxies.values())
    
    supported_regions = " | ".join([
        f"{config.get('name', region)} {config.get('flag', '')}"
        for region, config in sorted(REGION_CONFIG.items())
    ])

    html_content = template
    html_content = html_content.replace('{{GENERATED_TIME}}', get_generated_time())
    html_content = html_content.replace('{{TOTAL_NODES}}', str(len(all_nodes)))
    html_content = html_content.replace('{{TOTAL_REGIONS}}', str(len(region_results)))
    html_content = html_content.replace('{{TOTAL_PROXIES}}', str(total_proxies))
    html_content = html_content.replace('{{REGION_CARDS}}', '\n'.join(region_cards_html))
    html_content = html_content.replace('{{SUPPORTED_REGIONS}}', supported_regions)

    with open(f"{OUTPUT_DIR}/index.html", "w", encoding="utf-8") as f:
        f.write(html_content)

    logging.info(f"✓ 已生成网页: {OUTPUT_DIR}/index.html")
    logging.info(f"  - 包含 {len(region_results)} 个地区")
    logging.info(f"  - 共 {len(all_nodes)} 个IP节点")
    logging.info(f"  - 共 {total_proxies} 个代理节点")


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(DATA_DIR, exist_ok=True)

    logging.info(f"\n{'#'*70}")
    logging.info("Cloudflare IP 优选扫描器 V2.1 单域名版")
    logging.info(f"测试域名:{TRACE_DOMAIN}")
    logging.info("代理检测:API")
    logging.info(f"{'#'*70}\n")

    if not run_internal_tests():
        logging.error("内部自检未通过,程序退出")
        return

    logging.info("\n" + "="*60)
    logging.info("开始正式扫描...")
    logging.info("="*60)

    logging.info("\n获取 Cloudflare IP 范围...")
    cidrs = fetch_cf_ipv4_cidrs()
    if not cidrs:
        logging.error("无法获取 Cloudflare IP 段,程序退出")
        return

    total_ips = sum(cfg["sample"] for cfg in REGION_CONFIG.values())
    logging.info(f"生成 {total_ips} 个测试 IP...\n")
    all_test_ips = weighted_random_ips(cidrs, total_ips)

    all_results = []
    region_results = {}
    region_proxies = {}

    ip_offset = 0
    for region, config in REGION_CONFIG.items():
        sample_size = config["sample"]
        region_ips = all_test_ips[ip_offset:ip_offset + sample_size]
        ip_offset += sample_size

        proxies = get_proxies(region)
        region_proxies[region] = proxies

        raw = scan_region(region, region_ips, proxies)
        nodes = aggregate_nodes(raw)

        region_results[region] = nodes
        all_results.extend(raw)

        logging.info(f"{'='*60}")
        logging.info(f"✓ {region}: 发现 {len(nodes)} 个有效节点")
        logging.info(f"{'='*60}\n")

        time.sleep(1)

    all_nodes = aggregate_nodes(all_results)
    all_nodes.sort(key=lambda x: x["score"], reverse=True)

    logging.info(f"\n{'='*60}")
    logging.info(f"总计发现 {len(all_nodes)} 个节点")
    logging.info(f"{'='*60}\n")

    all_lines = [f'{n["ip"]}:{n["port"]}#{n["region"]}-score{n["score"]:.4f}\n' for n in all_nodes]
    with open(f"{OUTPUT_DIR}/ip_all.txt", "w", encoding="utf-8") as f:
        f.writelines(all_lines)

    for region, nodes in region_results.items():
        nodes.sort(key=lambda x: x["score"], reverse=True)
        top_nodes = nodes[:MAX_OUTPUT_PER_REGION]

        with open(f"{OUTPUT_DIR}/ip_{region}.txt", "w", encoding="utf-8") as f:
            for n in top_nodes:
                f.write(f'{n["ip"]}:{n["port"]}#{region}-score{n["score"]:.4f}\n')

        logging.info(f"{region}: 保存 {len(top_nodes)} 个节点")

    save_proxy_list(region_proxies)

    with open(f"{OUTPUT_DIR}/ip_candidates.json", "w", encoding="utf-8") as f:
        json.dump({
            "meta": {
                "generated_at": datetime.now(timezone.utc).isoformat() + "Z",
                "total_nodes": len(all_nodes),
                "regions": {r: len(nodes) for r, nodes in region_results.items()},
                "version": "2.1-single-domain",
                "test_domain": TRACE_DOMAIN,
                "proxy_check_method": "api",
                "total_proxies": sum(len(p) for p in region_proxies.values())
            },
            "nodes": all_nodes[:200]
        }, f, indent=2, ensure_ascii=False)

    generate_html(all_nodes, region_results, region_proxies)

    print("\n" + "="*60)
    print("📊 扫描统计")
    print("="*60)
    for region in sorted(region_results.keys()):
        nodes = region_results[region]
        proxies = region_proxies.get(region, [])
        if nodes:
            avg_score = sum(n["score"] for n in nodes) / len(nodes)
            print(f"{region:4s}: {len(nodes):3d} 节点 | {len(proxies):2d} 代理 | 平均分数: {avg_score:.3f}")
    print("="*60)
    print(f"总代理数: {sum(len(p) for p in region_proxies.values())}")
    print("="*60)

    logging.info("\n✅ 扫描完成!")
    logging.info(f"结果已保存到 {OUTPUT_DIR}/ 目录")
    logging.info("  - IP列表: ip_all.txt, ip_[REGION].txt")
    logging.info("  - 代理列表: proxy_all.txt, proxy_[REGION].txt")
    logging.info("  - JSON数据: ip_candidates.json")
    logging.info("  - HTML页面: index.html")


if __name__ == "__main__":
    main()
