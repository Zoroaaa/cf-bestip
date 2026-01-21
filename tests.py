# tests.py
import logging
import requests
import random
import time
import subprocess
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import fetch_cf_ipv4_cidrs

from config import *
from proxy_sources import (
    ProxyInfo,
    fetch_proxifly_proxies,
    fetch_proxydaily_proxies,
    fetch_tomcat1235_proxies,
    fetch_webshare_proxies
)


def check_proxy_with_api(proxy_info):
    """使用API检测代理的可用性和信息"""
    if not PROXY_CHECK_API_URL:
        logging.error("未配置 PROXY_CHECK_API_URL,无法检测代理")
        return {"success": False, "latency": 999999}

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

        location = result.get("location", {})
        country_code = location.get("country_code", "UNKNOWN")

        if proxy_info.country_code == "UNKNOWN":
            proxy_info.country_code = country_code

        proxy_info.api_result = result

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


def run_internal_tests():
    """运行内部可用性测试"""
    logging.info("\n" + "="*60)
    logging.info("开始内部测试...")
    logging.info("="*60)

    test_results = {
        "data_sources": {},
        "proxy_tests": {"working_count": 0, "total_tested": 0},
        "api_check": False,
        "cf_ip_fetch": False,
    }

    passed_tests = 0
    total_tests = 0

    # 测试 1: Cloudflare IP 段获取
    logging.info("\n[测试 1/4] Cloudflare IP 段获取...")
    try:
        cidrs = fetch_cf_ipv4_cidrs()
        if len(cidrs) > 0:
            logging.info(f"  ✓ 成功获取 {len(cidrs)} 个 IP 段")
            test_results["cf_ip_fetch"] = True
            passed_tests += 1
        else:
            logging.error("  ✗ IP 段列表为空")
    except Exception as e:
        logging.error(f"  ✗ 获取失败: {e}")
    total_tests += 1

    # 测试 2: 数据源测试
    logging.info("\n[测试 2/4] 代理数据源测试...")
    test_region = "US"

    sources = [
        ("proxifly",    lambda: fetch_proxifly_proxies(test_region, REGION_TO_COUNTRY_CODE)),
        ("proxydaily",  lambda: fetch_proxydaily_proxies(test_region, REGION_TO_COUNTRY_CODE, max_pages=1)),
        ("tomcat1235",  lambda: fetch_tomcat1235_proxies(test_region)),
        ("webshare",    lambda: fetch_webshare_proxies(test_region)),
    ]

    for name, func in sources:
        total_tests += 1
        try:
            proxies = func()
            count = len(proxies)
            test_results["data_sources"][name] = count > 0
            logging.info(f"    {name}: {count} 个代理")
            if count > 0:
                passed_tests += 1
        except Exception as e:
            test_results["data_sources"][name] = False
            logging.error(f"    ✗ {name} 失败: {e}")

    # 测试 3: API 可用性
    logging.info("\n[测试 3/4] 代理检测 API 测试...")
    total_tests += 1
    if not PROXY_CHECK_API_URL:
        logging.warning("  ⚠ 未配置 PROXY_CHECK_API_URL")
    else:
        try:
            params = {"token": PROXY_CHECK_API_TOKEN} if PROXY_CHECK_API_TOKEN else {}
            r = requests.get(PROXY_CHECK_API_URL, params=params, timeout=10)
            if r.status_code in (200, 400, 401):
                logging.info("  ✓ API 响应正常")
                test_results["api_check"] = True
                passed_tests += 1
            else:
                logging.warning(f"  ⚠ API 状态码异常: {r.status_code}")
        except Exception as e:
            logging.error(f"  ✗ API 测试失败: {e}")

    # 测试 4: 代理连通性抽样
    logging.info("\n[测试 4/4] 代理连通性测试...")
    all_test_proxies = []
    for name, func in sources:
        try:
            all_test_proxies.extend(func()[:3])
        except:
            pass

    working = 0
    tested = min(8, len(all_test_proxies))
    total_tests += 1

    if tested > 0 and PROXY_CHECK_API_URL:
        random.shuffle(all_test_proxies)
        for proxy in all_test_proxies[:tested]:
            result = check_proxy_with_api(proxy)
            if result["success"]:
                working += 1
                logging.info(f"    ✓ {proxy.host}:{proxy.port} ({proxy.type}) - {result['latency']}ms")
            time.sleep(0.4)

    test_results["proxy_tests"]["total_tested"] = tested
    test_results["proxy_tests"]["working_count"] = working

    if working > 0:
        logging.info(f"  ✓ {working}/{tested} 个代理可用")
        passed_tests += 1
    elif tested == 0:
        logging.info("  ℹ 无代理可测试")
    else:
        logging.warning("  ⚠ 抽样代理均不可用")

    # 测试总结
    logging.info("\n" + "="*60)
    logging.info("测试总结")
    logging.info("="*60)
    logging.info(f"通过检查: {passed_tests}/{total_tests}")

    # 核心要求：至少能拿到 CF IP 段
    # 其他项允许最多失败 1 个
    success = test_results["cf_ip_fetch"] and (passed_tests >= total_tests - 1)

    if success:
        logging.info("✅ 自检通过（允许部分非核心项失败）")
    else:
        logging.warning("⚠ 自检未完全通过，但核心项正常，将尝试继续运行")

    return success

