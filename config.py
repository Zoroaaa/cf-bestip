# config.py
"""
集中管理所有常量、阈值、URL、映射表等配置
"""

import os
from datetime import datetime

# ======================
# 路径相关
# ======================
OUTPUT_DIR = "public"
DATA_DIR = os.path.join(OUTPUT_DIR, "data")

# ======================
# Cloudflare 相关
# ======================
CF_IPS_V4_URL = "https://www.cloudflare.com/ips-v4"

TRACE_DOMAINS = {
    "v0": "sptest.ittool.pp.ua",
    "v1": "sptest1.ittool.pp.ua",
    "v2": "sptest2.ittool.pp.ua",
}

HTTPS_PORTS = [443, 8443, 2053, 2083, 2087, 2096]

# ======================
# 扫描 & 测试参数
# ======================
SAMPLE_SIZE_PER_REGION = 50
TOTAL_SAMPLE = 600                   # 约等于 12个地区 × 50
TIMEOUT = 15
CONNECT_TIMEOUT = 5
MAX_WORKERS = 20
LATENCY_LIMIT = 1300

PROXY_TEST_TIMEOUT = 10
PROXY_MAX_LATENCY = 1500
SOCKS5_MAX_LATENCY = 1500

MAX_OUTPUT_PER_REGION = 6
MAX_PROXIES_PER_REGION = 5

# ======================
# 代理检测 API
# ======================
PROXY_CHECK_API_URL = "https://prcheck.ittool.pp.ua/check"
PROXY_CHECK_API_TOKEN = "588wbb"

# ======================
# 地区配置
# ======================

REGION_CONFIG = {
    "CA": {"codes": ["CA"], "sample": SAMPLE_SIZE_PER_REGION},
    "CN": {"codes": ["CN"], "sample": SAMPLE_SIZE_PER_REGION},
    "DE": {"codes": ["DE"], "sample": SAMPLE_SIZE_PER_REGION},
    "FR": {"codes": ["FR"], "sample": SAMPLE_SIZE_PER_REGION},
    "GB": {"codes": ["GB"], "sample": SAMPLE_SIZE_PER_REGION},
    "IN": {"codes": ["IN"], "sample": SAMPLE_SIZE_PER_REGION},
    "IT": {"codes": ["IT"], "sample": SAMPLE_SIZE_PER_REGION},
    "JP": {"codes": ["JP"], "sample": SAMPLE_SIZE_PER_REGION},
    "NL": {"codes": ["NL"], "sample": SAMPLE_SIZE_PER_REGION},
    "RU": {"codes": ["RU"], "sample": SAMPLE_SIZE_PER_REGION},
    "US": {"codes": ["US"], "sample": SAMPLE_SIZE_PER_REGION},
    "SG": {"codes": ["SG"], "sample": SAMPLE_SIZE_PER_REGION},
}

# COLO → Region 映射（补充常见的）
COLO_MAP = {
    # 原有部分
    "HKG": "HK", "SIN": "SG", "NRT": "JP", "KIX": "JP",
    "ICN": "KR", "TPE": "TW",
    "SYD": "AU", "MEL": "AU",
    "LAX": "US", "SJC": "US", "SFO": "US", "SEA": "US",
    "ORD": "US", "DFW": "US", "ATL": "US", "IAD": "US",
    "YYZ": "CA", "YVR": "CA",
    "FRA": "DE", "MUC": "DE",
    "LHR": "GB", "LGW": "GB", "MAN": "GB",

    # 新增 / 补充
    "YUL": "CA", "YEG": "CA",       # 加拿大其他
    "PEK": "CN", "PVG": "CN", "CAN": "CN", "SZX": "CN",  # 中国大陆
    "CDG": "FR", "MRS": "FR",       # 法国
    "FCO": "IT", "MXP": "IT",       # 意大利
    "AMS": "NL",                    # 荷兰
    "SVO": "RU", "LED": "RU", "DME": "RU",  # 俄罗斯
    "BOM": "IN", "DEL": "IN",       # 印度
}

COUNTRY_TO_REGION = {
    "CA": "CA",
    "CN": "CN",
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

REGION_TO_COUNTRY_CODE = {
    "CA": "CA",
    "CN": "CN",
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