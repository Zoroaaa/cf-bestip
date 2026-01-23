# config.py
"""
集中管理所有常量、阈值、URL、映射表等配置
"""

import os
from datetime import datetime
import requests
import logging

# ======================
# 路径相关
# ======================
OUTPUT_DIR = "public"
DATA_DIR = os.path.join(OUTPUT_DIR, "data")

# ======================
# Cloudflare 相关
# ======================
CF_IPS_V4_URL = "https://www.cloudflare.com/ips-v4"

TRACE_DOMAIN = "sptest.ittool.pp.ua"

HTTPS_PORTS = [443, 8443, 2053, 2083, 2087, 2096]

# ======================
# 扫描 & 测试参数
# ======================
SAMPLE_SIZE_PER_REGION = 60
TOTAL_SAMPLE = 720                 
TIMEOUT = 15
CONNECT_TIMEOUT = 5
MAX_WORKERS = 24
LATENCY_LIMIT = 1300

PROXY_TEST_TIMEOUT = 10
PROXY_MAX_LATENCY = 1500
SOCKS5_MAX_LATENCY = 1500

MAX_OUTPUT_PER_REGION = 6
MAX_PROXIES_PER_REGION = 6

# ======================
# 代理检测 API
# ======================
PROXY_CHECK_API_URL = "https://prcheck.ittool.pp.ua/check"
PROXY_CHECK_API_TOKEN = "588wbb"

# ======================
# 第三方服务 Token
# ======================
# 从环境变量读取，如果没有则使用默认值
WEBSHARE_TOKEN = "fd6i0jla6026bmaeavorfjxrbu9dfbz9r5ne4asr"

# ======================
# 地区配置（完整版）
# ======================

REGION_CONFIG = {
    "CA": {"codes": ["CA"], "sample": SAMPLE_SIZE_PER_REGION, "name": "加拿大", "flag": "🇨🇦"},
    "HK": {"codes": ["HK"], "sample": SAMPLE_SIZE_PER_REGION, "name": "香港", "flag": "🇭🇰"},
    "DE": {"codes": ["DE"], "sample": SAMPLE_SIZE_PER_REGION, "name": "德国", "flag": "🇩🇪"},
    "FR": {"codes": ["FR"], "sample": SAMPLE_SIZE_PER_REGION, "name": "法国", "flag": "🇫🇷"},
    "GB": {"codes": ["GB"], "sample": SAMPLE_SIZE_PER_REGION, "name": "英国", "flag": "🇬🇧"},
    "IN": {"codes": ["IN"], "sample": SAMPLE_SIZE_PER_REGION, "name": "印度", "flag": "🇮🇳"},
    "IT": {"codes": ["IT"], "sample": SAMPLE_SIZE_PER_REGION, "name": "意大利", "flag": "🇮🇹"},
    "JP": {"codes": ["JP"], "sample": SAMPLE_SIZE_PER_REGION, "name": "日本", "flag": "🇯🇵"},
    "NL": {"codes": ["NL"], "sample": SAMPLE_SIZE_PER_REGION, "name": "荷兰", "flag": "🇳🇱"},
    "RU": {"codes": ["RU"], "sample": SAMPLE_SIZE_PER_REGION, "name": "俄罗斯", "flag": "🇷🇺"},
    "US": {"codes": ["US"], "sample": SAMPLE_SIZE_PER_REGION, "name": "美国", "flag": "🇺🇸"},
    "SG": {"codes": ["SG"], "sample": SAMPLE_SIZE_PER_REGION, "name": "新加坡", "flag": "🇸🇬"},
}

# ======================
# COLO → Region 映射（大幅扩充）
# ======================
COLO_MAP = {
    # 北美
    "YYZ": "CA", "YVR": "CA", "YUL": "CA", "YEG": "CA", "YYC": "CA",  # 加拿大
    "LAX": "US", "SJC": "US", "SFO": "US", "SEA": "US", "PDX": "US",  # 美国西海岸
    "ORD": "US", "DFW": "US", "ATL": "US", "IAD": "US", "EWR": "US",  # 美国中部/东部
    "MIA": "US", "PHX": "US", "DEN": "US", "BOS": "US", "MSP": "US",  # 美国其他
    "IAH": "US", "DTW": "US", "LAS": "US", "SLC": "US", "CLT": "US",
    
    # 亚太
    "HKG": "HK",  # 香港
    "SIN": "SG",  # 新加坡
    "NRT": "JP", "KIX": "JP", "HND": "JP",  # 日本
    "ICN": "KR", "GMP": "KR",  # 韩国
    "TPE": "TW",  # 台湾
    "SYD": "AU", "MEL": "AU", "BNE": "AU", "PER": "AU",  # 澳大利亚
    "AKL": "NZ",  # 新西兰
    "BKK": "TH",  # 泰国
    "KUL": "MY",  # 马来西亚
    "MNL": "PH",  # 菲律宾
    "CGK": "ID",  # 印尼
    "HAN": "VN", "SGN": "VN",  # 越南
    "BOM": "IN", "DEL": "IN", "MAA": "IN", "BLR": "IN",  # 印度
    
    # 中国大陆
    "PEK": "CN", "PVG": "CN", "CAN": "CN", "SZX": "CN", "CTU": "CN",
    "CKG": "CN", "XIY": "CN", "WUH": "CN", "HGH": "CN", "NKG": "CN",
    
    # 欧洲
    "LHR": "GB", "LGW": "GB", "MAN": "GB", "EDI": "GB",  # 英国
    "FRA": "DE", "MUC": "DE", "TXL": "DE", "HAM": "DE",  # 德国
    "CDG": "FR", "MRS": "FR", "ORY": "FR",  # 法国
    "AMS": "NL", "RTM": "NL",  # 荷兰
    "FCO": "IT", "MXP": "IT", "VCE": "IT",  # 意大利
    "MAD": "ES", "BCN": "ES",  # 西班牙
    "LIS": "PT",  # 葡萄牙
    "ZRH": "CH", "GVA": "CH",  # 瑞士
    "VIE": "AT",  # 奥地利
    "BRU": "BE",  # 比利时
    "CPH": "DK",  # 丹麦
    "OSL": "NO",  # 挪威
    "ARN": "SE", "STO": "SE",  # 瑞典
    "HEL": "FI",  # 芬兰
    "WAW": "PL",  # 波兰
    "PRG": "CZ",  # 捷克
    "BUD": "HU",  # 匈牙利
    "OTP": "RO",  # 罗马尼亚
    "ATH": "GR",  # 希腊
    "IST": "TR",  # 土耳其
    "SVO": "RU", "LED": "RU", "DME": "RU", "VKO": "RU",  # 俄罗斯
    
    # 中东
    "DXB": "AE", "AUH": "AE",  # 阿联酋
    "DOH": "QA",  # 卡塔尔
    "BAH": "BH",  # 巴林
    "KWI": "KW",  # 科威特
    "RUH": "SA", "JED": "SA",  # 沙特
    "TLV": "IL",  # 以色列
    "AMM": "JO",  # 约旦
    
    # 南美
    "GRU": "BR", "GIG": "BR", "BSB": "BR",  # 巴西
    "EZE": "AR", "AEP": "AR",  # 阿根廷
    "SCL": "CL",  # 智利
    "BOG": "CO",  # 哥伦比亚
    "LIM": "PE",  # 秘鲁
    
    # 非洲
    "JNB": "ZA", "CPT": "ZA",  # 南非
    "CAI": "EG",  # 埃及
    "LOS": "NG",  # 尼日利亚
    "NBO": "KE",  # 肯尼亚
}

# ======================
# Country Code → Region 映射（扩充）
# ======================
COUNTRY_TO_REGION = {
    "CA": "CA",  # 加拿大
    "HK": "HK",  # 香港
    "DE": "DE",  # 德国
    "FR": "FR",  # 法国
    "GB": "GB",  # 英国
    "IN": "IN",  # 印度
    "IT": "IT",  # 意大利
    "JP": "JP",  # 日本
    "NL": "NL",  # 荷兰
    "RU": "RU",  # 俄罗斯
    "US": "US",  # 美国
    "SG": "SG",  # 新加坡
    
    # 其他可能的代理来源国家，映射到最近的配置地区
    "KR": "JP",  # 韩国 → 日本
    "TW": "HK",  # 台湾 → 香港
    "AU": "SG",  # 澳大利亚 → 新加坡
    "TH": "SG",  # 泰国 → 新加坡
    "MY": "SG",  # 马来西亚 → 新加坡
    "PH": "SG",  # 菲律宾 → 新加坡
    "ID": "SG",  # 印尼 → 新加坡
    "VN": "SG",  # 越南 → 新加坡
    "CN": "HK",  # 中国 → 香港
    
    "ES": "FR",  # 西班牙 → 法国
    "PT": "FR",  # 葡萄牙 → 法国
    "CH": "DE",  # 瑞士 → 德国
    "AT": "DE",  # 奥地利 → 德国
    "BE": "NL",  # 比利时 → 荷兰
    "DK": "DE",  # 丹麦 → 德国
    "NO": "DE",  # 挪威 → 德国
    "SE": "DE",  # 瑞典 → 德国
    "FI": "RU",  # 芬兰 → 俄罗斯
    "PL": "DE",  # 波兰 → 德国
    "CZ": "DE",  # 捷克 → 德国
    "HU": "DE",  # 匈牙利 → 德国
    "RO": "RU",  # 罗马尼亚 → 俄罗斯
    "GR": "IT",  # 希腊 → 意大利
    "TR": "RU",  # 土耳其 → 俄罗斯
    
    "AE": "IN",  # 阿联酋 → 印度
    "QA": "IN",  # 卡塔尔 → 印度
    "SA": "IN",  # 沙特 → 印度
    
    "BR": "US",  # 巴西 → 美国
    "AR": "US",  # 阿根廷 → 美国
    "CL": "US",  # 智利 → 美国
    "MX": "US",  # 墨西哥 → 美国
    
    "ZA": "GB",  # 南非 → 英国
}

REGION_TO_COUNTRY_CODE = {
    "CA": "CA",
    "HK": "HK",
    "DE": "DE",
    "FR": "FR",
    "GB": "GB",
    "IN": "IN",
    "IT": "IT",
    "JP": "JP",
    "NL": "NL",
    "RU": "RU",
    "US": "US",
    "SG": "SG",
}

# ======================
# 日志 & 输出
# ======================
LOG_FORMAT = '%(asctime)s [%(levelname)s] %(message)s'
LOG_LEVEL = "INFO"


def get_generated_time():
    return datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')

def fetch_cf_ipv4_cidrs():
    """统一获取 Cloudflare IPv4 CIDR"""
    try:
        r = requests.get(CF_IPS_V4_URL, timeout=10)
        r.raise_for_status()
        return [
            line.strip()
            for line in r.text.splitlines()
            if line.strip() and not line.startswith("#")
        ]
    except Exception as e:
        logging.error(f"获取 Cloudflare IP 段失败: {e}")
        return []
