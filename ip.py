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
from datetime import datetime
from config import fetch_cf_ipv4_cidrs

from config import *
from proxy_sources import (
    ProxyInfo,
    fetch_proxifly_proxies,
    fetch_proxydaily_proxies,
    fetch_tomcat1235_proxies,
    fetch_webshare_proxies
)
from tests import check_proxy_with_api, run_internal_tests

import shutil

def check_runtime_dependencies():
    if shutil.which("curl") is None:
        logging.error("❌ 未检测到 curl，可执行文件不存在")
        logging.error("请确认运行环境已安装 curl")
        return False
    return True

if not check_runtime_dependencies():
    return

# ────────────────────────────────────────────────
# 日志配置
# ────────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format=LOG_FORMAT,
    handlers=[logging.StreamHandler()]
)


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

    expected_results = len(ips) * 0.2
    if len(raw_results) < expected_results:
        supplement_count = len(ips) // 2 if raw_results else len(ips)
        logging.info(f"⚠ 代理结果不足，使用直连补充 {supplement_count} 个IP...")

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

        logging.info(f"  ✓ 直连补充后总计: {len(raw_results)} 条结果")
    else:
        logging.info("  ✓ 代理结果充足，跳过直连补充")

    logging.info(f"✓ {region}: 总计收集 {len(raw_results)} 条测试结果\n")
    return raw_results


def get_proxies(region):
    all_proxies = []

    all_proxies.extend(fetch_proxifly_proxies(region, REGION_TO_COUNTRY_CODE))
    all_proxies.extend(fetch_proxydaily_proxies(region, REGION_TO_COUNTRY_CODE, max_pages=2))
    all_proxies.extend(fetch_tomcat1235_proxies(region))
    all_proxies.extend(fetch_webshare_proxies(region))

    target_country_code = REGION_TO_COUNTRY_CODE.get(region, region.upper())
    filtered_proxies = []

    for proxy in all_proxies:
        if proxy.country_code == target_country_code:
            filtered_proxies.append(proxy)
            continue
        mapped_region = COUNTRY_TO_REGION.get(proxy.country_code)
        if mapped_region == region:
            filtered_proxies.append(proxy)

    if not filtered_proxies:
        logging.warning(f"⚠ {region} 无匹配代理，使用全部代理")
        filtered_proxies = all_proxies

    logging.info(f"{region} 共收集 {len(filtered_proxies)} 个代理")

    if not filtered_proxies:
        return []

    socks5_proxies = [p for p in filtered_proxies if p.type == "socks5"]
    https_proxies = [p for p in filtered_proxies if p.type == "https"]

    test_proxies = (socks5_proxies[:30] + https_proxies[:30])[:50]

    logging.info(f"{region} 将测试 {len(test_proxies)} 个代理")

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
        return []

    socks5_list = [p for p in candidate_proxies if p.type == "socks5"]
    https_list = [p for p in candidate_proxies if p.type == "https"]

    socks5_list.sort(key=lambda x: x.tested_latency or 999999)
    https_list.sort(key=lambda x: x.tested_latency or 999999)

    best_proxies = socks5_list[:MAX_PROXIES_PER_REGION]
    remaining = MAX_PROXIES_PER_REGION - len(best_proxies)
    if remaining > 0:
        best_proxies.extend(https_list[:remaining])

    logging.info(f"✓ {region} 最终选出 {len(best_proxies)} 个代理:")
    for i, p in enumerate(best_proxies, 1):
        logging.info(f"  {i}. {p.host}:{p.port} ({p.type.upper()}) - 延迟:{p.tested_latency or 'N/A'}ms [src:{p.source}]")

    return best_proxies


def save_proxy_list(region_proxies):
    all_proxies_lines = []

    for region, proxies in region_proxies.items():
        for proxy in proxies:
            line = f"{proxy.host}:{proxy.port}#{region}_{proxy.tested_latency or 'N/A'}ms_{proxy.source}\n"
            all_proxies_lines.append(line)

    with open(f"{OUTPUT_DIR}/proxy_all.txt", "w", encoding="utf-8") as f:
        f.writelines(all_proxies_lines)

    logging.info(f"✓ 保存总代理列表: {len(all_proxies_lines)} 条 → proxy_all.txt")

    for region, proxies in region_proxies.items():
        lines = []
        for proxy in proxies:
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
        logging.error("未找到 template.html 文件，跳过 HTML 生成")
        return None


def generate_html(all_nodes, region_results, region_proxies):
    template = load_html_template()
    if not template:
        return

    region_cards_html = []

    for region in sorted(region_results.keys()):
        nodes = region_results[region]
        if not nodes:
            continue

        ip_items_html = []
        for node in nodes[:MAX_OUTPUT_PER_REGION]:
            min_latency = min(node['latencies'])
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
            proxy_html = f"""
            <div class="ip-item proxy-item">
                <div class="ip-address">{proxy.host}:{proxy.port}</div>
                <div class="ip-meta">
                    <span class="badge badge-latency">延迟 {proxy.tested_latency or 'N/A'}ms</span>
                    <span class="badge badge-colo">{proxy.type.upper()}</span>
                    <span class="badge badge-score">来源 {proxy.source}</span>
                </div>
            </div>"""
            proxy_items_html.append(proxy_html)

        proxy_section = ""
        if proxy_items_html:
            proxy_section = f"""
            <div class="proxy-list">
                <h4>推荐代理 ({len(proxies)})</h4>
                {''.join(proxy_items_html)}
            </div>"""

        card_html = f"""
        <div class="region-card">
            <div class="region-header">
                <span>{region}</span>
                <span class="region-count">{len(nodes)} 个节点</span>
            </div>
            <div class="region-body">
                <div class="ip-list">
                    {''.join(ip_items_html)}
                </div>
                {proxy_section}
                <div class="region-downloads">
                    <a href="ip_{region}.txt" class="region-download-btn btn-primary" download>📥 IP列表</a>
                    <a href="proxy_{region}.txt" class="region-download-btn btn-success" download>🔑 代理列表</a>
                </div>
            </div>
        </div>"""
        region_cards_html.append(card_html)

    total_proxies = sum(len(proxies) for proxies in region_proxies.values())

    html_content = template
    html_content = html_content.replace('{{GENERATED_TIME}}', get_generated_time())
    html_content = html_content.replace('{{TOTAL_NODES}}', str(len(all_nodes)))
    html_content = html_content.replace('{{TOTAL_REGIONS}}', str(len(region_results)))
    html_content = html_content.replace('{{TOTAL_PROXIES}}', str(total_proxies))
    html_content = html_content.replace('{{REGION_CARDS}}', '\n'.join(region_cards_html))

    with open(f"{OUTPUT_DIR}/index.html", "w", encoding="utf-8") as f:
        f.write(html_content)

    logging.info(f"✓ 已生成网页: {OUTPUT_DIR}/index.html")


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(DATA_DIR, exist_ok=True)

    logging.info(f"\n{'#'*70}")
    logging.info("Cloudflare IP 优选扫描器 V2.0 API Edition")
    logging.info("数据源：Proxifly + ProxyDaily + Tomcat1235 + Hookzof + Proxyscrape")
    logging.info(f"代理检测：API ({PROXY_CHECK_API_URL})")
    logging.info(f"{'#'*70}\n")

    if not run_internal_tests():
        logging.error("内部自检未通过，程序退出")
        return

    logging.info("\n" + "="*60)
    logging.info("开始正式扫描...")
    logging.info("="*60)

    logging.info("\n获取 Cloudflare IP 范围...")
    cidrs = fetch_cf_ipv4_cidrs()
    if not cidrs:
        logging.error("无法获取 Cloudflare IP 段，程序退出")
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

    # 保存总 IP 列表
    all_lines = [f'{n["ip"]}:{n["port"]}#{n["region"]}-score{n["score"]:.4f}\n' for n in all_nodes]
    with open(f"{OUTPUT_DIR}/ip_all.txt", "w", encoding="utf-8") as f:
        f.writelines(all_lines)

    # 按地区保存 IP
    for region, nodes in region_results.items():
        nodes.sort(key=lambda x: x["score"], reverse=True)
        top_nodes = nodes[:MAX_OUTPUT_PER_REGION]

        with open(f"{OUTPUT_DIR}/ip_{region}.txt", "w", encoding="utf-8") as f:
            for n in top_nodes:
                f.write(f'{n["ip"]}:{n["port"]}#{region}-score{n["score"]:.4f}\n')

        logging.info(f"{region}: 保存 {len(top_nodes)} 个节点")

    # 保存代理列表
    save_proxy_list(region_proxies)

    # 保存 JSON
    with open(f"{OUTPUT_DIR}/ip_candidates.json", "w", encoding="utf-8") as f:
        json.dump({
            "meta": {
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "total_nodes": len(all_nodes),
                "regions": {r: len(nodes) for r, nodes in region_results.items()},
                "version": "2.0-api",
                "data_sources": ["proxifly", "proxydaily", "tomcat1235", "hookzof", "proxyscrape"],
                "protocols": ["https", "socks5"],
                "proxy_check_method": "api",
                "total_proxies": sum(len(p) for p in region_proxies.values())
            },
            "nodes": all_nodes[:200]
        }, f, indent=2, ensure_ascii=False)

    # 生成 HTML
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