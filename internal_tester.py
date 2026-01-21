# internal_tester.py
import requests
import time
import logging
from models import ProxyInfo
from config import PROXY_CHECK_API_URL, PROXY_CHECK_API_TOKEN, CF_IPS_V4_URL, TRACE_DOMAINS
from data_sources import DataSourceManager
from proxy_tester import ProxyTester

class InternalTester:
    """内部可用性测试器"""
    
    def __init__(self):
        self.logger = logging.getLogger()
        self.data_source_manager = DataSourceManager()
        self.proxy_tester = ProxyTester()
    
    def run_all_tests(self):
        """运行所有内部测试"""
        self.logger.info("\n" + "="*60)
        self.logger.info("开始内部测试...")
        self.logger.info("="*60)
        
        test_results = {
            "data_sources": {},
            "proxy_tests": {},
            "api_check": None,
            "cf_ip_fetch": None,
            "cf_ip_test": None
        }
        
        # 运行各个测试
        test_results["cf_ip_fetch"] = self._test_cf_ip_fetch()
        test_results.update(self._test_data_sources())
        test_results["api_check"] = self._test_api_availability()
        test_results.update(self._test_proxy_connectivity())
        test_results["cf_ip_test"] = self._test_cf_ip_connectivity()
        
        # 输出测试总结
        return self._print_test_summary(test_results)
    
    def _test_cf_ip_fetch(self):
        """测试 Cloudflare IP 段获取"""
        self.logger.info("\n[测试 1/5] Cloudflare IP 段获取...")
        try:
            cidrs = self._fetch_cf_ipv4_cidrs()
            if len(cidrs) > 0:
                self.logger.info(f"  ✓ 成功获取 {len(cidrs)} 个 IP 段")
                return True
            else:
                self.logger.error("  ✗✗ IP 段列表为空")
                return False
        except Exception as e:
            self.logger.error(f"  ✗✗ 获取失败: {e}")
            return False
    
    def _test_data_sources(self):
        """测试数据源可用性"""
        self.logger.info("\n[测试 2/5] 代理数据源测试...")
        test_region = "US"
        results = {}
        
        # Proxifly
        self.logger.info("  测试 Proxifly...")
        try:
            proxifly_list = self.data_source_manager._fetch_proxifly_proxies(test_region)
            results["proxifly"] = len(proxifly_list) > 0
            self.logger.info(f"    ✓ Proxifly: {len(proxifly_list)} 个代理")
        except Exception as e:
            results["proxifly"] = False
            self.logger.error(f"    ✗✗ Proxifly 失败: {e}")
        
        # ProxyDaily
        self.logger.info("  测试 ProxyDaily...")
        try:
            proxydaily_list = self.data_source_manager._fetch_proxydaily_proxies(test_region, max_pages=1)
            results["proxydaily"] = len(proxydaily_list) > 0
            self.logger.info(f"    ✓ ProxyDaily: {len(proxydaily_list)} 个代理")
        except Exception as e:
            results["proxydaily"] = False
            self.logger.error(f"    ✗✗ ProxyDaily 失败: {e}")
        
        # Tomcat1235
        self.logger.info("  测试 Tomcat1235...")
        try:
            tomcat_list = self.data_source_manager._fetch_tomcat1235_proxies(test_region)
            results["tomcat1235"] = len(tomcat_list) > 0
            self.logger.info(f"    ✓ Tomcat1235: {len(tomcat_list)} 个代理")
        except Exception as e:
            results["tomcat1235"] = False
            self.logger.error(f"    ✗✗ Tomcat1235 失败: {e}")
        
        return {"data_sources": results}
    
    def _test_api_availability(self):
        """测试 API 可用性"""
        self.logger.info("\n[测试 3/5] 代理检测 API 测试...")
        if not PROXY_CHECK_API_URL:
            self.logger.warning("  ⚠⚠⚠ 未配置 PROXY_CHECK_API_URL,跳过API测试")
            return False
        
        try:
            # 使用一个测试代理测试API
            test_proxy = ProxyInfo("8.8.8.8", 1080, "socks5", source="test")
            result = self.proxy_tester._check_proxy_with_api(test_proxy)
            if result.get("success") or "latency" in result:
                self.logger.info("  ✓ API 响应正常")
                return True
            else:
                self.logger.warning("  ⚠⚠⚠ API 响应异常")
                return False
        except Exception as e:
            self.logger.error(f"  ✗✗ API 测试失败: {e}")
            return False
    
    def _test_proxy_connectivity(self):
        """测试代理连通性"""
        self.logger.info("\n[测试 4/5] 代理连通性测试...")
        
        # 收集一些测试代理
        all_test_proxies = []
        test_region = "US"
        
        try:
            proxifly_list = self.data_source_manager._fetch_proxifly_proxies(test_region)
            all_test_proxies.extend(proxifly_list[:3])
        except:
            pass
        
        try:
            proxydaily_list = self.data_source_manager._fetch_proxydaily_proxies(test_region, max_pages=1)
            all_test_proxies.extend(proxydaily_list[:3])
        except:
            pass
        
        results = {"working_count": 0, "total_tested": 0}
        
        if all_test_proxies and PROXY_CHECK_API_URL:
            self.logger.info(f"  测试 {len(all_test_proxies[:5])} 个代理...")
            working_proxies = 0
            
            for proxy in all_test_proxies[:5]:  # 最多测试5个
                result = self.proxy_tester._check_proxy_with_api(proxy)
                if result["success"]:
                    working_proxies += 1
                    self.logger.info(f"    ✓ {proxy.host}:{proxy.port} ({proxy.type}) - {result['latency']}ms")
            
            results["working_count"] = working_proxies
            results["total_tested"] = len(all_test_proxies[:5])
            
            if working_proxies > 0:
                self.logger.info(f"  ✓ {working_proxies}/{len(all_test_proxies[:5])} 个代理可用")
            else:
                self.logger.warning("  ⚠⚠⚠ 没有可用代理")
        else:
            self.logger.warning("  ⚠⚠⚠ 无代理可测试或API未配置")
        
        return {"proxy_tests": results}
    
    def _test_cf_ip_connectivity(self):
        """测试 Cloudflare IP 连通性"""
        self.logger.info("\n[测试 5/5] Cloudflare IP 测试...")
        try:
            cidrs = self._fetch_cf_ipv4_cidrs()
            test_ips = self._weighted_random_ips(cidrs, 5)
            self.logger.info(f"  测试 {len(test_ips)} 个 Cloudflare IP...")
            
            # 简单测试第一个IP
            test_ip = str(test_ips[0])
            result = self._curl_test_with_proxy(test_ip, "sptest.ittool.pp.ua", None)
            
            if result:
                self.logger.info(f"    ✓ 测试成功: {result['ip']} -> {result['region']} ({result['latency']}ms)")
                return True
            else:
                self.logger.warning("    ⚠⚠⚠ CF IP 测试未返回结果")
                return False
        except Exception as e:
            self.logger.error(f"  ✗✗ CF IP 测试失败: {e}")
            return False
    
    def _print_test_summary(self, test_results):
        """输出测试总结"""
        self.logger.info("\n" + "="*60)
        self.logger.info("测试总结")
        self.logger.info("="*60)
        
        passed_tests = 0
        total_tests = 0
        
        # CF IP 段
        total_tests += 1
        if test_results["cf_ip_fetch"]:
            self.logger.info("✓ Cloudflare IP 段获取: 通过")
            passed_tests += 1
        else:
            self.logger.error("✗✗ Cloudflare IP 段获取: 失败")
        
        # 数据源
        for source, status in test_results["data_sources"].items():
            total_tests += 1
            if status:
                self.logger.info(f"✓ 数据源 {source}: 通过")
                passed_tests += 1
            else:
                self.logger.warning(f"⚠ 数据源 {source}: 失败(非致命)")
        
        # API 检测
        total_tests += 1
        if test_results["api_check"]:
            self.logger.info("✓ 代理检测 API: 通过")
            passed_tests += 1
        else:
            self.logger.warning("⚠ 代理检测 API: 未配置或失败(非致命)")
        
        # 代理测试
        total_tests += 1
        proxy_working = test_results["proxy_tests"].get("working_count", 0)
        if proxy_working > 0:
            self.logger.info(f"✓ 代理连通性: 通过 ({proxy_working} 个可用)")
            passed_tests += 1
        else:
            self.logger.warning("⚠ 代理连通性: 无可用代理(将使用直连)")
        
        # CF IP 测试
        total_tests += 1
        if test_results["cf_ip_test"]:
            self.logger.info("✓ CF IP 测试: 通过")
            passed_tests += 1
        else:
            self.logger.error("✗✗ CF IP 测试: 失败")
        
        self.logger.info("="*60)
        self.logger.info(f"测试结果: {passed_tests}/{total_tests} 通过")
        
        if passed_tests >= total_tests - 2:  # 允许最多2个非关键测试失败
            self.logger.info("✅ 系统可用性测试通过,可以开始扫描")
            return True
        else:
            self.logger.error("❌❌ 系统可用性测试失败,请检查网络和依赖")
            return False
    
    # 工具函数（从主文件复制）
    def _fetch_cf_ipv4_cidrs(self):
        """获取Cloudflare IP段"""
        r = requests.get(CF_IPS_V4_URL, timeout=10)
        r.raise_for_status()
        return [x.strip() for x in r.text.splitlines() if x.strip()]
    
    def _weighted_random_ips(self, cidrs, total):
        """加权随机IP生成"""
        import random
        import ipaddress
        
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
    
    def _curl_test_with_proxy(self, ip, domain, proxy=None):
        """简化版curl测试（用于内部测试）"""
        import subprocess
        
        try:
            cmd = ["curl", "-k", "-o", "/dev/null", "-s"]
            
            if proxy:
                if proxy.type in ['socks5', 'socks4']:
                    cmd.extend(["--socks5", f"{proxy.host}:{proxy.port}"])
                else:
                    cmd.extend(["-x", f"http://{proxy.host}:{proxy.port}"])
            
            cmd.extend([
                "-w", "%{time_connect} %{time_appconnect} %{http_code}",
                "--connect-timeout", "5",
                "--max-time", "10",
                "--resolve", f"{domain}:443:{ip}",
                f"https://{domain}"
            ])
            
            out = subprocess.check_output(cmd, timeout=15, stderr=subprocess.DEVNULL)
            parts = out.decode().strip().split()
            
            if len(parts) < 3:
                return None
            
            tc, ta, code = parts[0], parts[1], parts[2]
            
            if code in ["000", "0"]:
                return None
            
            latency = int((float(tc) + float(ta)) * 1000)
            
            # 简化版只检查基本连通性
            if latency > 3000:
                return None
            
            return {
                "ip": str(ip),
                "domain": domain,
                "latency": latency,
                "region": "TEST"
            }
            
        except subprocess.TimeoutExpired:
            return None
        except Exception as e:
            self.logger.debug(f"内部测试失败: {ip} - {e}")
            return None