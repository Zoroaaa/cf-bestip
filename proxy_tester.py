# proxy_tester.py
import requests
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from models import ProxyInfo
from config import PROXY_CHECK_API_URL, PROXY_CHECK_API_TOKEN, MAX_WORKERS
from config import PROXY_TEST_TIMEOUT, PROXY_MAX_LATENCY, SOCKS5_MAX_LATENCY
from config import REGION_TO_COUNTRY_CODE, COUNTRY_TO_REGION

class ProxyTester:
    """代理测试器"""
    
    def __init__(self):
        self.logger = logging.getLogger()
    
    def test_proxies(self, proxies, region):
        """测试代理列表"""
        if not proxies:
            return []
        
        # 地区过滤和映射
        target_country_code = REGION_TO_COUNTRY_CODE.get(region, region.upper())
        filtered_proxies = []
        
        for proxy in proxies:
            if proxy.country_code == target_country_code:
                filtered_proxies.append(proxy)
                continue
            
            mapped_region = COUNTRY_TO_REGION.get(proxy.country_code)
            if mapped_region == region:
                filtered_proxies.append(proxy)
                continue
        
        if not filtered_proxies:
            self.logger.warning(f"⚠ {region} 无匹配的代理,尝试使用所有可用代理")
            filtered_proxies = proxies
        
        # 限制测试数量(优先 SOCKS5)
        socks5_proxies = [p for p in filtered_proxies if p.type == "socks5"]
        https_proxies = [p for p in filtered_proxies if p.type == "https"]
        
        test_proxies = (socks5_proxies[:30] + https_proxies[:30])[:50]
        
        self.logger.info(f"{region} 测试 {len(test_proxies)} 个代理")
        
        # 并发测试
        candidate_proxies = []
        
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_proxy = {executor.submit(self._check_proxy_with_api, p): p for p in test_proxies}
            
            for future in as_completed(future_to_proxy):
                proxy = future_to_proxy[future]
                try:
                    test_result = future.result()
                    if test_result["success"]:
                        candidate_proxies.append(proxy)
                except Exception as e:
                    self.logger.debug(f"代理测试异常: {e}")
        
        return self._select_best_proxies(candidate_proxies, region)
    
    def _check_proxy_with_api(self, proxy_info):
        """使用API检测代理的可用性"""
        if not PROXY_CHECK_API_URL:
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
            self.logger.debug(f"代理 {proxy_info.host}:{proxy_info.port} API检测失败: {e}")
            return {"success": False, "latency": 999999, "https_ok": False}
    
    def _select_best_proxies(self, candidate_proxies, region):
        """选择最佳代理"""
        if not candidate_proxies:
            self.logger.warning(f"⚠ {region} 无可用代理,将完全使用直连")
            return []
        
        # 按协议和延迟排序(SOCKS5 优先)
        socks5_list = [p for p in candidate_proxies if p.type == "socks5"]
        https_list = [p for p in candidate_proxies if p.type == "https"]
        
        socks5_list.sort(key=lambda x: x.tested_latency)
        https_list.sort(key=lambda x: x.tested_latency)
        
        # 组合:优先 SOCKS5
        best_proxies = socks5_list[:5]  # MAX_PROXIES_PER_REGION
        remaining = 5 - len(best_proxies)
        if remaining > 0:
            best_proxies.extend(https_list[:remaining])
        
        self.logger.info(f"✓ {region} 最终选出 {len(best_proxies)} 个代理:")
        for i, p in enumerate(best_proxies, 1):
            self.logger.info(f"  {i}. {p.host}:{p.port} ({p.type.upper()}) - 延迟:{p.tested_latency}ms")
        
        return best_proxies