# config.py
import os

# =========================
# 基础参数
# =========================
CF_IPS_V4_URL = "https://www.cloudflare.com/ips-v4"

TRACE_DOMAINS = {
    "v0": "sptest.ittool.pp.ua",
    "v1": "sptest1.ittool.pp.ua",
    "v2": "sptest2.ittool.pp.ua",
}

SAMPLE_SIZE = 600
TIMEOUT = 15
CONNECT_TIMEOUT = 5
MAX_WORKERS = 20
LATENCY_LIMIT = 1300

OUTPUT_DIR = "public"
DATA_DIR = "public/data"

HTTPS_PORTS = [443, 8443, 2053, 2083, 2087, 2096]

# 代理检测 API 配置
PROXY_CHECK_API_URL = "https://prcheck.ittool.pp.ua/check"
PROXY_CHECK_API_TOKEN = "588wbb"

# 目标地区配置 - 去掉AU TW UK，增加IT FR
REGION_CONFIG = {
    "HK": {"codes": ["HK"], "sample": 60},
    "SG": {"codes": ["SG"], "sample": 60},
    "JP": {"codes": ["JP"], "sample": 60},
    "KR": {"codes": ["KR"], "sample": 60},
    "US": {"codes": ["US"], "sample": 60},
    "DE": {"codes": ["DE"], "sample": 60},
    "CA": {"codes": ["CA"], "sample": 60},
    "IT": {"codes": ["IT"], "sample": 60},  # 新增
    "FR": {"codes": ["FR"], "sample": 60},  # 新增
}

MAX_OUTPUT_PER_REGION = 6
MAX_PROXIES_PER_REGION = 5

# 代理测试配置
PROXY_TEST_TIMEOUT = 10
PROXY_MAX_LATENCY = 1500
SOCKS5_MAX_LATENCY = 1500

# =========================
# COLO → Region 映射
# =========================
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
    "FCO": "IT", "LIN": "IT", "MXP": "IT",  # 新增意大利colo
    "CDG": "FR", "ORY": "FR",  # 新增法国colo
}

# 国家代码到地区的映射 - 更新映射
COUNTRY_TO_REGION = {
    "HK": "HK", "SG": "SG", "JP": "JP", "KR": "KR", "TW": "TW",
    "US": "US", "DE": "DE", "GB": "UK", "AU": "AU", "CA": "CA",
    "IT": "IT", "FR": "FR",  # 新增
    "NL": "DE", "ES": "DE", "CH": "DE", "BE": "DE", "AT": "DE",
    "BR": "US", "MX": "US", "AR": "US",
    "IN": "SG", "TH": "SG", "ID": "SG", "MY": "SG", "PH": "SG",
}

# =========================
# 数据源配置
# =========================
PROXIFLY_BASE_URL = "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/countries/{}/data.txt"
PROXIFLY_JSON_URL = "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/countries/{}/data.json"

REGION_TO_COUNTRY_CODE = {
    "HK": "HK", "SG": "SG", "JP": "JP", "KR": "KR", "TW": "TW",
    "US": "US", "DE": "DE", "UK": "GB", "AU": "AU", "CA": "CA",
    "IT": "IT", "FR": "FR",  # 新增
}

# 数据源地区映射配置
DATA_SOURCE_REGION_MAPPING = {
    "proxifly": {
        "HK": "HK", "SG": "SG", "JP": "JP", "KR": "KR", "TW": "TW",
        "US": "US", "DE": "DE", "CA": "CA", "IT": "IT", "FR": "FR"
    },
    "proxydaily": {
        "IT": "IT", "FR": "FR",  # proxydaily只测试IT和FR
        "US": "US"  # 保留US作为默认
    },
    "tomcat1235": {
        "US": "US"  # tomcat1235固定测试US
    }
}
