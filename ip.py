import subprocess
import random
import ipaddress
import time
import requests
import os
import json
import math
from datetime import datetime, timedelta
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

# =========================
# 参数区
# =========================

CF_IPS_V4_URL = "https://www.cloudflare.com/ips-v4"

TRACE_DOMAINS = [
    "sptest.ittool.pp.ua",
    "sptest1.ittool.pp.ua",
    "sptest2.ittool.pp.ua",
]

SAMPLE_SIZE = 800
TIMEOUT = 4
MAX_WORKERS = 30
LATENCY_LIMIT = 800

EMA_ALPHA = 0.35
DAY_MATURE = 7
FAIL_BASE = 0.85
STATE_KEEP_DAYS = 7

OUTPUT_DIR = "public"
STATE_DIR = "data"

HTTPS_PORTS = [443, 8443, 2053, 2083, 2087, 2096]

REGION_WHITELIST = {
    "HK", "SG", "JP", "KR",
    "US", "DE", "UK",
    "TW", "AU", "CA"
}

MAX_OUTPUT_PER_REGION = 32

# =========================
# Cloudflare Colo → Region
# =========================

COLO_MAP = {
    "HKG": "HK", "SIN": "SG", "NRT": "JP", "KIX": "JP",
    "ICN": "KR", "TPE": "TW",
    "SYD": "AU", "MEL": "AU",
    "LAX": "US", "SFO": "US", "SEA": "US", "ORD": "US",
    "FRA": "DE", "MUC": "DE",
    "LHR": "UK", "LGW": "UK",
    "YYZ": "CA", "YVR": "CA",
}

# =========================

def ensure_dirs():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(STATE_DIR, exist_ok=True)

def cleanup_old_states(today):
    for fn in os.listdir(STATE_DIR):
        if fn.startswith("ip_state_") and fn.endswith(".json"):
            date_str = fn.replace("ip_state_", "").replace(".json", "")
            try:
                file_date = datetime.strptime(date_str, "%Y-%m-%d")
                if (today - file_date).days >= STATE_KEEP_DAYS:
                    os.remove(os.path.join(STATE_DIR, fn))
            except ValueError:
                pass

def load_prev_state(today):
    prev_day = today - timedelta(days=1)
    fn = f"{STATE_DIR}/ip_state_{prev_day.strftime('%Y-%m-%d')}.json"
    if os.path.exists(fn):
        with open(fn, "r") as f:
            return json.load(f)
    return {}

def save_today_state(today, state):
    fn = f"{STATE_DIR}/ip_state_{today.strftime('%Y-%m-%d')}.json"
    with open(fn, "w") as f:
        json.dump(state, f, indent=2)

# =========================

def fetch_cf_ipv4_cidrs():
    r = requests.get(CF_IPS_V4_URL, timeout=10)
    r.raise_for_status()
    return [x.strip() for x in r.text.splitlines() if x.strip()]

def weighted_random_ips(cidrs, total):
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

def test_ip(ip, domain):
    try:
        cmd = [
            "curl", "-sI",
            "--resolve", f"{domain}:443:{ip}",
            f"https://{domain}",
            "--max-time", str(TIMEOUT)
        ]
        start = time.time()
        out = subprocess.check_output(cmd, timeout=TIMEOUT + 1)
        latency = int((time.time() - start) * 1000)

        if latency > LATENCY_LIMIT:
            return None

        headers = out.decode(errors="ignore").lower()
        ray = None
        for line in headers.splitlines():
            if line.startswith("cf-ray"):
                ray = line.split(":")[1].strip()

        if not ray:
            return None

        colo = ray.split("-")[-1].upper()
        region = COLO_MAP.get(colo, "OTHER")

        latency_score = max(0.0, 1 - latency / LATENCY_LIMIT)

        return {
            "ip": str(ip),
            "domain": domain,
            "latency": latency,
            "latency_score": latency_score,
            "colo": colo,
            "region": region
        }
    except Exception:
        return None

def calc_stable_score(ema, days, fail):
    return round(
        ema
        * min(1.0, days / DAY_MATURE)
        * math.pow(FAIL_BASE, fail),
        4
    )

# =========================

def main():
    today = datetime.utcnow()
    ensure_dirs()
    cleanup_old_states(today)

    prev_state = load_prev_state(today)

    cidrs = fetch_cf_ipv4_cidrs()
    ips = weighted_random_ips(cidrs, SAMPLE_SIZE)

    raw = []
    with ThreadPoolExecutor(MAX_WORKERS) as pool:
        for domain in TRACE_DOMAINS:
            for r in pool.map(lambda x: test_ip(x, domain), ips):
                if r:
                    raw.append(r)

    views = defaultdict(list)
    for r in raw:
        views[r["ip"]].append(r)

    today_state = {}
    seen_ips = set()

    for ip, vlist in views.items():
        seen_ips.add(ip)

        avg = sum(v["latency_score"] for v in vlist) / len(vlist)
        lats = [v["latency"] for v in vlist]
        std = (sum((x - sum(lats)/len(lats))**2 for x in lats) / len(lats))**0.5
        score = round(avg * max(0, 1 - std / LATENCY_LIMIT), 4)

        prev = prev_state.get(ip)
        if prev:
            ema = round(EMA_ALPHA * score + (1 - EMA_ALPHA) * prev["ema_score"], 4)
            days = prev["days"] + 1
            fail = max(0, prev["fail_count"] - 1)
        else:
            ema = score
            days = 1
            fail = 0

        best = min(vlist, key=lambda x: x["latency"])

        today_state[ip] = {
            "ema_score": ema,
            "last_score": score,
            "days": days,
            "fail_count": fail,
            "stable_score": calc_stable_score(ema, days, fail),
            "region": best["region"],
            "colo": best["colo"]
        }

    for ip, prev in prev_state.items():
        if ip not in seen_ips:
            fail = prev["fail_count"] + 1
            today_state[ip] = {
                **prev,
                "fail_count": fail,
                "stable_score": calc_stable_score(prev["ema_score"], prev["days"], fail)
            }

    save_today_state(today, today_state)

    stable_sorted = sorted(
        today_state.items(),
        key=lambda x: x[1]["stable_score"],
        reverse=True
    )

    with open(f"{OUTPUT_DIR}/ip_stable.json", "w") as f:
        json.dump(
            [{"ip": ip, **data} for ip, data in stable_sorted],
            f, indent=2
        )

    region_files = defaultdict(list)
    for ip, data in stable_sorted:
        if data["region"] in REGION_WHITELIST:
            region_files[data["region"]].append(
                f"{ip}:443#{data['region']}-{data['stable_score']}\n"
            )

    for r, lines in region_files.items():
        with open(f"{OUTPUT_DIR}/ip_stable_{r}.txt", "w") as f:
            f.writelines(lines[:MAX_OUTPUT_PER_REGION])

    print("[*] Done.")

if __name__ == "__main__":
    main()