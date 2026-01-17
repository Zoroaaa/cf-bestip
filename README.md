
CF IP Auto Selector

一个基于 Cloudflare Worker + cf-ray 的 Cloudflare 优选 IP 自动筛选工具，
通过 GitHub Actions 定时运行，自动生成 低延迟、可用的 Cloudflare IP 列表，并按地区输出。


---

✨ 项目特点

✅ 官方 Cloudflare IP 段（自动拉取）

✅ 真实 POP 节点探测（基于 cf-ray）

✅ 按延迟排序

✅ 按地区拆分输出

✅ 每个地区可限制最大数量

✅ GitHub Actions 全自动运行

✅ GitHub Pages 直接发布结果

✅ 无需 VPS / 无需五地服务器


适用于：

V2Ray / VMess / Trojan / Reality

自建订阅 / 优选订阅生成器

Cloudflare Worker / Argo Tunnel 架构



---

📁 输出文件说明

所有输出文件默认位于：

public/

1️⃣ 全量结果

文件	说明

ip_all.txt	所有通过检测的 IP（不限制数量）
ip_all.json	全量结构化数据（包含延迟、colo、region）


TXT 格式示例：

104.16.12.34:443#HK-132ms
172.64.88.9:2053#SG-158ms


---

2️⃣ 按地区输出（重点）

每个地区会生成一个文件：

ip_HK.txt
ip_SG.txt
ip_JP.txt
ip_KR.txt
ip_US.txt
...

📌 每个地区默认最多输出 32 条（可配置）


---

⚙️ 核心原理说明

工作流程

1. 拉取 Cloudflare 官方 IPv4 网段


2. 按网段权重随机抽样 IP


3. 使用 curl + --resolve：

强制指定 IP

请求你的 Worker 域名



4. 解析响应头中的 cf-ray


5. 提取 POP 节点（colo）


6. 映射为地区（HK / SG / JP / KR / US 等）


7. 过滤高延迟 IP


8. 按延迟排序


9. 生成 TXT / JSON 文件




---

🧠 地区判断机制（重要）

地区不是 IP 归属地

而是 Cloudflare 实际接入的 POP 节点

判断依据：

cf-ray: xxxxxxx-HKG


映射规则在代码中集中维护：

COLO_MAP = {
    "HKG": "HK",
    "SIN": "SG",
    "NRT": "JP",
    "ICN": "KR",
    "LAX": "US",
    ...
}


---

🧩 参数配置说明

位于 ip.py 顶部：

SAMPLE_SIZE = 800          # 抽样 IP 数
TIMEOUT = 4               # curl 超时（秒）
MAX_WORKERS = 30          # 并发线程数
LATENCY_LIMIT = 800       # 最大可接受延迟 ms

MAX_OUTPUT_PER_REGION = 32  # 每个地区最大输出数量

推荐配置（GitHub Actions）

SAMPLE_SIZE: 600–1000

MAX_WORKERS: 25–35

LATENCY_LIMIT: 600–900



---

🚀 GitHub Actions 使用方式

1️⃣ 添加工作流

.github/workflows/run.yml

name: CF IP Auto Selector

on:
  schedule:
    - cron: "0 3 * * *"
  workflow_dispatch:

jobs:
  run:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Run script
        run: |
          python ip.py

      - name: Publish to GitHub Pages
        uses: peaceiris/actions-gh-pages@v4
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          publish_dir: public
          publish_branch: gh-pages


---

🌐 GitHub Pages 访问

启用 Pages 后，可直接通过：

https://<你的用户名>.github.io/<仓库名>/ip_HK.txt

用于：

客户端订阅

二次加工

自动拉取



---

⚠️ 已知限制（真实情况）

Cloudflare IP 并不绑定固定地区

同一个 IP：

今天可能 HK

明天可能 US


地区结果 取决于你的探测出口

GitHub Actions 出口在 美国 → US 偏多是正常现象



---

🧭 后续可扩展方向（未实现）

🔄 地区不足自动补扫

🎯 强制亚洲偏向策略

🌏 多 Worker / 多出口协同

📊 历史延迟统计

🔁 自动淘汰劣质 IP



---

📜 License

MIT
仅供学习与研究使用，请遵守当地法律法规。


