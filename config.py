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

# COLO → Region 映射
COLO_MAP = {
    "HKG": "HK", "SIN": "SG", "NRT": "JP", "KIX": "JP",
    "ICN": "KR", "TPE": "TW",
    "SYD": "AU", "MEL": "AU",
    "LAX": "US", "SJC": "US", "SFO": "US",
    "SEA": "US", "ORD": "US", "DFW": "US",
    "ATL": "US", "IAD": "US", "EWR": "US",
    "JFK": "US", "BOS": "US", "MIA": "US",
    "PHX": "US", "DEN": "US", "IAH": "US",
    "FRA": "DE", "MUC": "DE", "AMS": "DE",
    "LHR": "UK", "LGW": "UK", "MAN": "UK",
    "YYZ": "CA", "YVR": "CA",
}

COUNTRY_TO_REGION = {
    "HK": "HK", "SG": "SG", "JP": "JP", "KR": "KR", "TW": "TW",
    "US": "US", "DE": "DE", "GB": "UK", "AU": "AU", "CA": "CA",
    "FR": "DE", "NL": "DE", "IT": "DE", "ES": "DE",
    "BR": "US", "MX": "US", "AR": "US",
    "IN": "SG", "TH": "SG", "ID": "SG", "MY": "SG",
}

REGION_TO_COUNTRY_CODE = {
    "HK": "HK", "SG": "SG", "JP": "JP", "KR": "KR", "TW": "TW",
    "US": "US", "DE": "DE", "UK": "GB", "AU": "AU", "CA": "CA",
}

# ======================
# 日志 & 输出
# ======================
LOG_FORMAT = '%(asctime)s [%(levelname)s] %(message)s'
LOG_LEVEL = "INFO"


def get_generated_time():
    return datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')