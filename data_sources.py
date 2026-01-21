import requests
import ipaddress
import time
import logging
import random
from bs4 import BeautifulSoup
from models import ProxyInfo
from config import PROXIFLY_BASE_URL, PROXIFLY_JSON_URL, REGION_TO_COUNTRY_CODE, COUNTRY_TO_REGION

class DataSourceManager:
    """数据源管理器"""
    
    def __init__(self):
        self.logger = logging.getLogger()
    
    def fetch_all_proxies(self, region):
        """从所有数据源获取代理"""
        all_proxies = []
        
        # 数据源 1: Proxifly
        proxifly_proxies = self._fetch_proxifly_proxies(region)
        all_proxies.extend(proxifly_proxies)
        
        # 数据源 2: ProxyDaily (修复版)
        proxydaily_proxies = self._fetch_proxydaily_proxies(region, max_pages=2)
        all_proxies.extend(proxydaily_proxies)
        
        # 数据源 3: Tomcat1235
        tomcat_proxies = self._fetch_tomcat1235_proxies(region)
        all_proxies.extend(tomcat_proxies)
        
        self.logger.info(f"{region} 共收集 {len(all_proxies)} 个代理")
        return all_proxies
    
    def _fetch_proxifly_proxies(self, region):
        """从 Proxifly 获取代理列表"""
        country_code = REGION_TO_COUNTRY_CODE.get(region)
        if not country_code:
            return []

        proxies = []
        
        # 尝试 JSON 格式
        json_url = PROXIFLY_JSON_URL.format(country_code)
        try:
            self.logger.info(f"[Proxifly] 获取 {region} 的代理 (JSON)...")
            response = requests.get(json_url, timeout=15)
            response.raise_for_status()
            
            data = response.json()
            for item in data:
                try:
                    protocol = item.get('protocol', 'http').lower()
                    if protocol not in ['https', 'socks5']:
                        if protocol == 'http':
                            protocol = 'https'
                        elif protocol.startswith('socks'):
                            protocol = 'socks5'
                        else:
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
                except (KeyError, ValueError, TypeError):
                    continue
                    
            self.logger.info(f"  ✓ Proxifly: {region} 获取 {len(proxies)} 个代理 (JSON)")
            return proxies
            
        except Exception as e:
            self.logger.debug(f"Proxifly JSON 失败: {e}, 尝试 TXT 格式...")
        
        # 回退到 TXT 格式
        txt_url = PROXIFLY_BASE_URL.format(country_code)
        try:
            response = requests.get(txt_url, timeout=15)
            response.raise_for_status()
            
            lines = response.text.strip().split('\n')
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                try:
                    proxy_type = 'https'
                    if line.startswith('http://'):
                        proxy_type = 'https'
                        line = line.replace('http://', '')
                    elif line.startswith('https://'):
                        proxy_type = 'https'
                        line = line.replace('https://', '')
                    elif line.startswith('socks5://'):
                        proxy_type = 'socks5'
                        line = line.replace('socks5://', '')
                    elif line.startswith('socks4://'):
                        proxy_type = 'socks5'
                        line = line.replace('socks4://', '')
                    
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
            
            self.logger.info(f"  ✓ Proxifly: {region} 获取 {len(proxies)} 个代理 (TXT)")
            return proxies
            
        except Exception as e:
            self.logger.error(f"  ✗ Proxifly: {region} 失败 - {e}")
            return []

    def _fetch_proxydaily_proxies(self, region, max_pages=3):
        """从 ProxyDaily 获取代理列表 - 修复版"""
        proxies = []
        session = requests.Session()
        
        # 使用 proxydaily.py 中的请求头
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
            "Cache-Control": "max-age=0",
            "Priority": "u=0, i",
            "sec-ch-ua": '"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
        }
        
        country_code = REGION_TO_COUNTRY_CODE.get(region, "")
        
        self.logger.info(f"[ProxyDaily] 获取 {region} 的代理...")
        
        for page in range(1, max_pages + 1):
            try:
                # 使用 proxydaily.py 中的参数格式
                params = {
                    "draw": f"{page}",
                    "columns[0][data]": "ip", "columns[0][name]": "ip", "columns[0][searchable]": "true", "columns[0][orderable]": "false",
                    "columns[0][search][value]": "", "columns[0][search][regex]": "false",
                    "columns[1][data]": "port", "columns[1][name]": "port", "columns[1][searchable]": "true", "columns[1][orderable]": "false",
                    "columns[1][search][value]": "", "columns[1][search][regex]": "false",
                    "columns[2][data]": "protocol", "columns[2][name]": "protocol", "columns[2][searchable]": "true", "columns[2][orderable]": "false",
                    "columns[2][search][value]": "", "columns[2][search][regex]": "false",
                    "columns[3][data]": "speed", "columns[3][name]": "speed", "columns[3][searchable]": "true", "columns[3][orderable]": "false",
                    "columns[3][search][value]": "", "columns[3][search][regex]": "false",
                    "columns[4][data]": "anonymity", "columns[4][name]": "anonymity", "columns[4][searchable]": "true", "columns[4][orderable]": "false",
                    "columns[4][search][value]": "", "columns[4][search][regex]": "false",
                    "columns[5][data]": "country", "columns[5][name]": "country", "columns[5][searchable]": "true", "columns[5][orderable]": "false",
                    "columns[5][search][value]": "", "columns[5][search][regex]": "false",
                    "start": f"{(page - 1) * 100}",
                    "length": "100",
                    "search[value]": "",
                    "search[regex]": "false",
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
                        
                        # 地区过滤
                        if country_code and item_country != country_code:
                            mapped_region = COUNTRY_TO_REGION.get(item_country)
                            if mapped_region != region:
                                continue
                        
                        # 使用 proxydaily.py 中的协议选择逻辑
                        protocols = item.get('protocol', 'http').split(',')
                        protocol = random.choice(protocols).strip().lower()
                        
                        # 协议过滤和标准化
                        if protocol not in ['https', 'socks5']:
                            if protocol in ['http', 'https']:
                                protocol = 'https'
                            elif protocol.startswith('socks'):
                                protocol = 'socks5'
                            else:
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
                        
                    except (KeyError, ValueError, TypeError) as e:
                        self.logger.debug(f"ProxyDaily 数据处理错误: {e}")
                        continue
                
                self.logger.info(f"  ProxyDaily 第 {page} 页: 获取 {len(data_items)} 条数据")
                time.sleep(0.5)  # 避免请求过快
                
            except Exception as e:
                self.logger.debug(f"ProxyDaily 第 {page} 页失败: {e}")
                continue
        
        self.logger.info(f"  ✓ ProxyDaily: {region} 获取 {len(proxies)} 个代理")
        return proxies

    def _fetch_tomcat1235_proxies(self, region):
        """从 Tomcat1235 获取代理列表"""
        proxies = []
        session = requests.Session()
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        self.logger.info(f"[Tomcat1235] 获取 {region} 的代理...")
        
        try:
            url = 'https://tomcat1235.nyc.mn/proxy_list?page=1'
            resp = session.get(url, headers=headers, timeout=20)
            resp.raise_for_status()
            resp.encoding = 'utf-8'
            
            soup = BeautifulSoup(resp.text, 'html.parser')
            table = soup.find('table')
            if not table:
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
                    
                    ipaddress.ip_address(host)
                    
                    if protocol not in ['https', 'socks5']:
                        if protocol in ['http', 'https']:
                            protocol = 'https'
                        elif protocol.startswith('socks'):
                            protocol = 'socks5'
                        else:
                            continue
                    
                    proxy = ProxyInfo(
                        host=host,
                        port=port,
                        proxy_type=protocol,
                        country_code="UNKNOWN",
                        source="tomcat1235"
                    )
                    proxies.append(proxy)
                    
                except (ValueError, ipaddress.AddressValueError, IndexError):
                    continue
            
            time.sleep(0.5)
            
        except Exception as e:
            self.logger.debug(f"Tomcat1235 请求失败: {e}")
        
        self.logger.info(f"  ✓ Tomcat1235: {region} 获取 {len(proxies)} 个代理")
        return proxies
