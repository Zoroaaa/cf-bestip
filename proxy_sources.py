import requests
import logging
from bs4 import BeautifulSoup
import ipaddress
import time

class ProxyInfo:
    """统一的代理信息类"""
    def __init__(self, host, port, proxy_type, country_code=None, anonymity=None, 
                 delay=None, source="unknown", username=None, password=None):
        self.host = host
        self.port = port
        self.type = proxy_type.lower()  # https, socks5
        self.country_code = country_code.upper() if country_code else "UNKNOWN"
        self.anonymity = anonymity
        self.delay = delay
        self.source = source
        self.tested_latency = None
        self.https_ok = False
        self.api_result = None  # 保存API返回的完整结果
        
        # 直接在初始化时处理认证信息
        if username and password:
            self.api_result = {
                "username": username,
                "password": password
            }
        
    def to_dict(self):
        result = {
            "host": self.host,
            "port": self.port,
            "type": self.type,
            "country_code": self.country_code,
            "source": self.source,
            "tested_latency": self.tested_latency,
            "https_ok": self.https_ok
        }
        # 如果有认证信息，添加到字典
        if self.api_result and self.api_result.get("username"):
            result["auth"] = {
                "username": self.api_result["username"],
                "password": self.api_result["password"]
            }
        return result
    
    def get_proxy_url(self, protocol="http"):
        """
        获取完整的代理URL（包含认证信息）
        
        Args:
            protocol: 协议类型，默认 "http"
            
        Returns:
            str: 完整的代理URL
        """
        if self.api_result and self.api_result.get("username"):
            username = self.api_result["username"]
            password = self.api_result["password"]
            return f"{protocol}://{username}:{password}@{self.host}:{self.port}"
        else:
            return f"{protocol}://{self.host}:{self.port}"
    
    def __repr__(self):
        auth_info = "[AUTH]" if (self.api_result and self.api_result.get("username")) else ""
        return f"Proxy({self.host}:{self.port}, {self.type}, {self.country_code}, src={self.source}){auth_info}"


def fetch_proxifly_proxies(region, REGION_TO_COUNTRY_CODE):
    """从 Proxifly 获取代理列表"""
    country_code = REGION_TO_COUNTRY_CODE.get(region)
    if not country_code:
        logging.warning(f"Proxifly: {region} 无对应的国家代码")
        return []

    proxies = []
    
    # 尝试 JSON 格式
    json_url = f"https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/countries/{country_code}/data.json"
    try:
        logging.info(f"[Proxifly] 获取 {region} 的代理 (JSON)...")
        response = requests.get(json_url, timeout=15)
        response.raise_for_status()
        
        data = response.json()
        for item in data:
            try:
                protocol = item.get('protocol', '').lower()
                
                # 只接受 https 和 socks5，抛弃 http 和 socks4
                if protocol not in ['https', 'socks5']:
                    continue
                
                proxy = ProxyInfo(
                    host=item['ip'],
                    port=int(item['port']),
                    proxy_type=protocol,
                    country_code=item.get('geolocation', {}).get('country', country_code),
                    anonymity=item.get('anonymity'),
                    source="proxifly"
                )
                proxies.append(proxy)
            except (KeyError, ValueError, TypeError) as e:
                logging.debug(f"Proxifly JSON 解析错误: {e}")
                continue
                
        logging.info(f"  ✓ Proxifly: {region} 获取 {len(proxies)} 个代理 (JSON)")
        return proxies
        
    except Exception as e:
        logging.debug(f"Proxifly JSON 失败: {e}, 尝试 TXT 格式...")
    
    # 回退到 TXT 格式
    txt_url = f"https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/countries/{country_code}/data.txt"
    try:
        response = requests.get(txt_url, timeout=15)
        response.raise_for_status()
        
        lines = response.text.strip().split('\n')
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            try:
                proxy_type = None
                
                # 只接受 https:// 和 socks5://，抛弃 http:// 和 socks4://
                if line.startswith('https://'):
                    proxy_type = 'https'
                    line = line.replace('https://', '')
                elif line.startswith('socks5://'):
                    proxy_type = 'socks5'
                    line = line.replace('socks5://', '')
                elif line.startswith('http://') or line.startswith('socks4://'):
                    continue  # 抛弃 http 和 socks4
                else:
                    # 没有前缀，默认尝试 https
                    proxy_type = 'https'
                
                parts = line.split(':')
                if len(parts) >= 2:
                    host = parts[0].strip()
                    port = int(parts[1].strip())
                    ipaddress.ip_address(host)
                    
                    proxy = ProxyInfo(
                        host=host,
                        port=port,
                        proxy_type=proxy_type,
                        country_code=country_code,
                        source="proxifly"
                    )
                    proxies.append(proxy)
            except (ValueError, ipaddress.AddressValueError, IndexError):
                continue
        
        logging.info(f"  ✓ Proxifly: {region} 获取 {len(proxies)} 个代理 (TXT)")
        return proxies
        
    except Exception as e:
        logging.error(f"  ✗ Proxifly: {region} 失败 - {e}")
        return []


def fetch_proxydaily_proxies(region, REGION_TO_COUNTRY_CODE, max_pages=3):
    """从 ProxyDaily 获取代理列表"""
    proxies = []
    session = requests.Session()
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
        "Accept": "application/json",
    }
    
    country_code = REGION_TO_COUNTRY_CODE.get(region, "")
    
    logging.info(f"[ProxyDaily] 获取 {region} 的代理...")
    
    for page in range(1, max_pages + 1):
        try:
            params = {
                "draw": f"{page}",
                "start": f"{(page - 1) * 100}",
                "length": "100",
                "search[value]": "",
                "_": f"{int(time.time() * 1000)}"
            }
            
            resp = session.get(
                'https://proxy-daily.com/api/serverside/proxies',
                headers=headers,
                params=params,
                timeout=15
            )
            resp.raise_for_status()
            data_items = resp.json().get('data', [])
            
            for item in data_items:
                try:
                    item_country = item.get('country', '').upper()
                    
                    # 地区过滤:优先匹配目标地区
                    if country_code and item_country != country_code:
                        continue
                    
                    protocols = item.get('protocol', '').split(',')
                    for protocol in protocols:
                        protocol = protocol.strip().lower()
                        
                        # 只接受 https 和 socks5，抛弃 http 和 socks4
                        if protocol not in ['https', 'socks5']:
                            continue
                        
                        proxy = ProxyInfo(
                            host=item['ip'],
                            port=int(item['port']),
                            proxy_type=protocol,
                            country_code=item_country,
                            anonymity=item.get('anonymity', '').lower(),
                            delay=item.get('speed'),
                            source="proxydaily"
                        )
                        proxies.append(proxy)
                        
                except (KeyError, ValueError, TypeError):
                    continue
            
            time.sleep(0.5)  # 避免请求过快
            
        except Exception as e:
            logging.debug(f"ProxyDaily 第 {page} 页失败: {e}")
            continue
    
    logging.info(f"  ✓ ProxyDaily: {region} 获取 {len(proxies)} 个代理")
    return proxies


def fetch_tomcat1235_proxies(region):
    """从 Tomcat1235 获取代理列表"""
    proxies = []
    session = requests.Session()
    
    headers = {
        'User-Agent': (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/91.0.4472.124 Safari/537.36'
        )
    }
    
    logging.info(f"[Tomcat1235] 获取 {region} 的代理...")
    
    try:
        # Tomcat1235 免费版固定只有第一页
        url = 'https://tomcat1235.nyc.mn/proxy_list?page=1'
        resp = session.get(url, headers=headers, timeout=20)
        resp.raise_for_status()
        resp.encoding = 'utf-8'
        
        soup = BeautifulSoup(resp.text, 'html.parser')
        table = soup.find('table')
        if not table:
            logging.debug("Tomcat1235 页面中未找到代理表格")
            return proxies
        
        trs = table.find_all('tr')[1:]
        
        for row in trs:
            cells = row.find_all('td')
            if len(cells) < 3:
                continue
            
            try:
                protocol = cells[0].text.strip().lower()
                host = cells[1].text.strip()
                port = int(cells[2].text.strip())
                
                # 验证 IP 格式
                ipaddress.ip_address(host)
                
                # 只接受 https 和 socks5，抛弃 http 和 socks4
                if protocol not in ['https', 'socks5']:
                    continue
                
                proxy = ProxyInfo(
                    host=host,
                    port=port,
                    proxy_type=protocol,
                    country_code="UNKNOWN",  # 需要后续通过 API 检测补充
                    source="tomcat1235"
                )
                proxies.append(proxy)
                
            except (ValueError, ipaddress.AddressValueError, IndexError):
                continue
        
        time.sleep(0.5)
        
    except Exception as e:
        logging.debug(f"Tomcat1235 请求失败: {e}")
    
    logging.info(f"  ✓ Tomcat1235: {region} 获取 {len(proxies)} 个代理 (国家码需API补充)")
    return proxies


def fetch_monosans_socks5_proxies(region):
    """从 monosans/proxy-list 获取 SOCKS5 代理列表"""
    proxies = []
    url = "https://raw.githubusercontent.com/monosans/proxy-list/refs/heads/main/proxies/socks5.txt"
    
    logging.info(f"[MonosansProxyList] 获取 {region} 的 SOCKS5 代理...")
    
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        
        lines = response.text.strip().split('\n')
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            try:
                # 数据格式: IP:PORT
                parts = line.split(':')
                if len(parts) != 2:
                    continue
                
                host = parts[0].strip()
                port = int(parts[1].strip())
                
                # 验证 IP 格式
                ipaddress.ip_address(host)
                
                proxy = ProxyInfo(
                    host=host,
                    port=port,
                    proxy_type='socks5',
                    country_code="UNKNOWN",  # 需要后续通过 API 检测补充
                    source="monosans"
                )
                proxies.append(proxy)
                
            except (ValueError, ipaddress.AddressValueError, IndexError):
                continue
        
        logging.info(f"  ✓ MonosansProxyList: 获取 {len(proxies)} 个 SOCKS5 代理 (国家码需API补充)")
        return proxies
        
    except Exception as e:
        logging.error(f"  ✗ MonosansProxyList 获取失败: {e}")
        return []