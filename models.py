# models.py
class ProxyInfo:
    """统一的代理信息类"""
    def __init__(self, host, port, proxy_type, country_code=None, anonymity=None, 
                 delay=None, source="unknown"):
        self.host = host
        self.port = port
        self.type = proxy_type.lower()  # http, https, socks5, socks4
        self.country_code = country_code.upper() if country_code else "UNKNOWN"
        self.anonymity = anonymity
        self.delay = delay
        self.source = source
        self.tested_latency = None
        self.https_ok = False
        self.api_result = None  # 保存API返回的完整结果
        
    def to_dict(self):
        return {
            "host": self.host,
            "port": self.port,
            "type": self.type,
            "country_code": self.country_code,
            "source": self.source,
            "tested_latency": self.tested_latency,
            "https_ok": self.https_ok
        }
    
    def __repr__(self):
        return f"Proxy({self.host}:{self.port}, {self.type}, {self.country_code}, src={self.source})"