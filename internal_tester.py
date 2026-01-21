# internal_tester.py
import requests
import time
import logging
import random
from models import ProxyInfo
from config import PROXY_CHECK_API_URL, PROXY_CHECK_API_TOKEN, CF_IPS_V4_URL, TRACE_DOMAINS
from config import REGION_CONFIG, REGION_TO_COUNTRY_CODE
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
                self.logger.error("  ✗✗✗✗ IP 段列表为空")
                return False
        except Exception as e:
            self.logger.error(f"  ✗✗✗✗ 获取失败: {e}")
            return False
    
    def _test_data_sources(self):
        """测试数据源可用性"""
        self.logger.info("\n[测试 2/5] 代理数据源测试...")
        # 随机选择一个地区进行数据源测试
        available_regions = list(REGION_CONFIG.keys())
        test_region = random.choice(available_regions)
        self.logger.info(f"  随机选择测试地区: {test_region}")
        
        results = {}
        
        # Proxifly
        self.logger.info("  测试 Proxifly...")
        try:
            proxifly_list = self.data_source_manager._fetch_proxifly_proxies(test_region)
            results["proxifly"] = len(proxifly_list) > 0
            self.logger.info(f"    ✓ Proxifly: {len(proxifly_list)} 个代理")
        except Exception as e:
            results["proxifly"] = False
            self.logger.error(f"    ✗✗✗✗ Proxifly 失败: {e}")
        
        # ProxyDaily
        self.logger.info("  测试 ProxyDaily...")
        try:
            proxydaily_list = self.data_source_manager._fetch_proxydaily_proxies(test_region)
            results["proxydaily"] = len(proxydaily_list) > 0
            self.logger.info(f"    ✓ ProxyDaily: {len(proxydaily_list)} 个代理")
        except Exception as e:
            results["proxydaily"] = False
            self.logger.error(f"    ✗✗✗✗ ProxyDaily 失败: {e}")
        
        # Tomcat1235
        self.logger.info("  测试 Tomcat1235...")
        try:
            tomcat_list = self.data_source_manager._fetch_tomcat1235_proxies(test_region)
            results["tomcat1235"] = len(tomcat_list) > 0
            self.logger.info(f"    ✓ Tomcat1235: {len(tomcat_list)} 个代理")
        except Exception as e:
            results["tomcat1235"] = False
            self.logger.error(f"    ✗✗✗✗ Tomcat1235 失败: {e}")
        
        return {"data_sources": results}
    
    def _test_api_availability(self):
        """测试 API 可用性"""
        self.logger.info("\n[测试 3/5] 代理检测 API 测试...")
        if not PROXY_CHECK_API_URL:
            self.logger.warning("  ⚠⚠⚠⚠⚠ 未配置 PROXY_CHECK_API_URL,跳过API测试")
            return False
        
        try:
            # 使用一个测试代理测试API
            test_proxy = ProxyInfo("8.8.8.8", 1080, "socks5", source="test")
            result = self.proxy_tester._check_proxy_with_api(test_proxy)
            if result.get("success") or "latency" in result:
                self.logger.info("  ✓ API 响应正常")
                return True
            else:
                self.logger.warning("  ⚠⚠⚠⚠⚠ API 响应异常")
                return False
        except Exception as e:
            self.logger.error(f"  ✗✗✗✗ API 测试失败: {e}")
            return False
    
    def _test_proxy_connectivity(self):
        """测试代理连通性 - 从所有数据源随机获取代理进行测试"""
        self.logger.info("\n[测试 4/5] 代理连通性测试...")
        
        # 收集所有数据源的所有地区代理
        all_proxies_by_source = {}
        available_regions = list(REGION_CONFIG.keys())
        
        self.logger.info("  从所有地区收集代理...")
        
        # 从每个数据源获取所有地区的代理
        for source_name in ["proxifly", "proxydaily", "tomcat1235"]:
            all_proxies_by_source[source_name] = []
            
            # 随机选择几个地区进行测试，避免测试时间过长
            test_regions = random.sample(available_regions, min(3, len(available_regions)))
            self.logger.info(f"  {source_name} 测试地区: {', '.join(test_regions)}")
            
            for region in test_regions:
                try:
                    if source_name == "proxifly":
                        proxies = self.data_source_manager._fetch_proxifly_proxies(region)
                    elif source_name == "proxydaily":
                        proxies = self.data_source_manager._fetch_proxydaily_proxies(region)
                    elif source_name == "tomcat1235":
                        proxies = self.data_source_manager._fetch_tomcat1235_proxies(region)
                    
                    if proxies:
                        all_proxies_by_source[source_name].extend(proxies)
                        self.logger.info(f"    {region}: {len(proxies)} 个代理")
                        
                except Exception as e:
                    self.logger.debug(f"    {source_name} {region} 获取失败: {e}")
        
        results = {"working_count": 0, "total_tested": 0, "source_results": {}}
        
        if all_proxies_by_source and PROXY_CHECK_API_URL:
            total_tested = 0
            total_working = 0
            
            for source_name, proxy_list in all_proxies_by_source.items():
                if len(proxy_list) == 0:
                    self.logger.info(f"  {source_name}: 无代理可用")
                    results["source_results"][source_name] = {"tested": 0, "working": 0}
                    continue
                
                # 随机抽取5个代理（如果可用代理少于5个，则使用全部）
                sample_size = min(5, len(proxy_list))
                sampled_proxies = random.sample(proxy_list, sample_size)
                
                self.logger.info(f"\n  {source_name} 随机抽取 {sample_size} 个代理:")
                for i, proxy in enumerate(sampled_proxies, 1):
                    region_info = f"({proxy.country_code})" if proxy.country_code != "UNKNOWN" else ""
                    self.logger.info(f"    {i}. {proxy.host}:{proxy.port} {proxy.type.upper()} {region_info}")
                
                # 测试抽取的代理
                self.logger.info(f"  {source_name} 代理测试结果:")
                source_working = 0
                
                for i, proxy in enumerate(sampled_proxies, 1):
                    result = self.proxy_tester._check_proxy_with_api(proxy)
                    if result["success"]:
                        source_working += 1
                        total_working += 1
                        self.logger.info(f"    {i}. ✓ {proxy.host}:{proxy.port} - {result['latency']}ms")
                    else:
                        self.logger.info(f"    {i}. ✗ {proxy.host}:{proxy.port} - 失败")
                
                total_tested += sample_size
                results["source_results"][source_name] = {
                    "tested": sample_size, 
                    "working": source_working,
                    "success_rate": round(source_working / sample_size * 100, 1) if sample_size > 0 else 0
                }
                
                self.logger.info(f"  {source_name}: {source_working}/{sample_size} 可用 ({results['source_results'][source_name]['success_rate']}%)")
            
            results["working_count"] = total_working
            results["total_tested"] = total_tested
            
            if total_working > 0:
                overall_rate = round(total_working / total_tested * 100, 1) if total_tested > 0 else 0
                self.logger.info(f"\n  ✓ 总体: {total_working}/{total_tested} 个代理可用 ({overall_rate}%)")
            else:
                self.logger.warning("  ⚠⚠⚠⚠⚠ 没有可用代理")
        else:
            self.logger.warning("  ⚠⚠⚠⚠⚠ 无代理可测试或API未配置")
        
        return {"proxy_tests": results}
    
    def _test_cf_ip_connectivity(self):
        """测试 Cloudflare IP 连通性"""
        self.logger.info("\n[测试 5/5] Cloudflare IP 测试...")
        try:
            cidrs = self._fetch_cf_ipv4_cidrs()
            test_ips = self._weighted_random_ips(cidrs, 5)
            self.logger.info(f"  测试 {len(test_ips)} 个 Cloudflare IP...")
            
            # 测试所有5个IP
            successful_tests = 0
            test_domain = "sptest.ittool.pp.ua"
            
            for i, test_ip in enumerate(test_ips, 1):
                ip_str = str(test_ip)
                self.logger.info(f"    测试第 {i} 个IP: {ip_str}")
                
                result = self._curl_test_with_proxy(ip_str, test_domain, None)
                
                if result:
                    successful_tests += 1
                    self.logger.info(f"      ✓ {ip_str} -> {result.get('region', 'UNKNOWN')} ({result['latency']}ms)")
                else:
                    self.logger.info(f"      ✗ {ip_str} -> 连接失败")
            
            success_rate = (successful_tests / len(test_ips)) * 100
            
            if successful_tests > 0:
                self.logger.info(f"  ✓ Cloudflare IP 测试: {successful_tests}/{len(test_ips)} 成功 ({success_rate:.1f}%)")
                return True
            else:
                self.logger.warning(f"  ⚠⚠⚠⚠⚠ Cloudflare IP 测试: 0/{len(test_ips)} 成功")
                return False
                
        except Exception as e:
            self.logger.error(f"  ✗✗✗✗ CF IP 测试失败: {e}")
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
            self.logger.error("✗✗✗✗ Cloudflare IP 段获取: 失败")
        
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
        
        # 代理测试 - 详细输出每个数据源的结果
        proxy_results = test_results["proxy_tests"]
        source_results = proxy_results.get("source_results", {})
        
        total_tests += 1
        proxy_working = proxy_results.get("working_count", 0)
        proxy_tested = proxy_results.get("total_tested", 0)
        
        if proxy_tested > 0:
            # 输出每个数据源的详细结果
            self.logger.info("✓ 代理连通性测试完成:")
            for source_name, result in source_results.items():
                success_rate = result.get("success_rate", 0)
                working = result.get("working", 0)
                tested = result.get("tested", 0)
                status_icon = "✓" if success_rate > 50 else "⚠"
                self.logger.info(f"  {status_icon} {source_name}: {working}/{tested} 可用 ({success_rate}%)")
            
            overall_rate = round(proxy_working / proxy_tested * 100, 1) if proxy_tested > 0 else 0
            self.logger.info(f"  总体: {proxy_working}/{proxy_tested} 可用 ({overall_rate}%)")
            
            if proxy_working > 0:
                passed_tests += 1
            else:
                self.logger.warning("⚠ 代理连通性: 无可用代理(将使用直连)")
        else:
            self.logger.warning("⚠ 代理连通性: 无代理可测试(将使用直连)")
        
        # CF IP 测试
        total_tests += 1
        if test_results["cf_ip_test"]:
            self.logger.info("✓ CF IP 测试: 通过")
            passed_tests += 1
        else:
            self.logger.error("✗✗✗✗ CF IP 测试: 失败")
        
        self.logger.info("="*60)
        self.logger.info(f"测试结果: {passed_tests}/{total_tests} 通过")
        
        if passed_tests >= total_tests - 2:  # 允许最多2个非关键测试失败
            self.logger.info("✅ 系统可用性测试通过,可以开始扫描")
            return True
        else:
            self.logger.error("❌❌❌❌ 系统可用性测试失败,请检查网络和依赖")
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
