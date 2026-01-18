
Cloudflare 优选 IP 探测与评分工具

项目简介

这是一个用于 Cloudflare IPv4 Anycast IP 探测、测速、评分与区域归类 的自动化工具。

项目目标并不是“跑满全球节点”，而是通过 真实 TLS 握手 + 多视角测速 + 稳定性评分 的方式，筛选出 在当前运行环境下实际可用、延迟低、稳定性较好的 Cloudflare IP，为后续代理、反代、Worker、订阅生成等场景提供可靠的 IP 数据来源。

本工具 不依赖 Cloudflare API，完全基于公开 IP 段与真实网络请求结果，具备较强的现实参考价值。


---

核心功能

1. Cloudflare IPv4 段获取

自动从 Cloudflare 官方地址获取 IPv4 CIDR 列表

保证 IP 来源权威、实时

避免硬编码或第三方维护列表失效问题



---

2. 按 CIDR 权重随机抽样 IP

根据每个 CIDR 的地址规模进行 加权随机抽样

避免小段 IP 被过度放大

保证整体抽样分布更贴近真实 Cloudflare 网络结构


默认抽样规模：

SAMPLE_SIZE = 1000


---

3. 多视角 Trace 域名测试

通过多个不同的测速域名（Trace Domain），对同一 IP 进行多次测试：

TRACE_DOMAINS = {
    "v0": "sptest.ittool.pp.ua",
    "v1": "sptest1.ittool.pp.ua",
    "v2": "sptest2.ittool.pp.ua",
}

每个 IP 会被测试多个视角，用于判断：

是否偶发可用

是否存在明显抖动

是否具备稳定连接能力



---

4. 真实 TLS 连接测速（非 Ping）

每次测试均通过 curl 发起真实 HTTPS 请求：

强制 TLS 1.3

HTTP/1.1

完整 TCP + TLS 握手过程

获取：

time_connect

time_appconnect

HTTP 状态码



最终延迟计算方式：

latency = (TCP连接时间 + TLS握手时间) × 1000

这比 ICMP Ping 更贴近真实代理使用场景。


---

5. Cloudflare 节点识别（COLO → Region）

从响应头中解析 cf-ray

提取 Cloudflare COLO 代码（如 HKG / NRT / LAX）

映射为区域代码（HK / JP / US 等）


示例：

cf-ray: 8c1234567890abcd-HKG

映射后：

colo = HKG
region = HK


---

6. 延迟与稳定性评分体系

每个 IP 会基于多个维度计算综合评分：

评分因子

1. 可用视角比例（稳定性）


2. 多次测试延迟波动（一致性）


3. 最低延迟表现（性能）



评分公式（逻辑简化说明）：

score = 稳定性 × 一致性 × 延迟表现

评分范围：0 ~ 1
分数越高，说明该 IP 更稳定、延迟更低


---

7. 区域白名单控制

只保留指定区域的 IP，避免无效或不可控地区：

REGION_WHITELIST = {
    "HK", "SG", "JP", "KR",
    "US", "DE", "UK",
    "TW", "AU", "CA"
}

这对于代理、反代、订阅生成非常关键。


---

8. 区域级数量上限控制

每个区域最多输出指定数量的 IP，防止某一区域“刷屏”：

MAX_OUTPUT_PER_REGION = 32

适合后续做：

订阅节点生成

负载均衡池

Worker / Argo Tunnel 入口池



---

9. 结果结构化输出（面向后处理）

每个节点包含以下核心信息：

{
  "ip": "x.x.x.x",
  "port": 443,
  "region": "JP",
  "colo": "NRT",
  "latencies": [120, 135, 128],
  "score": 0.82
}

为后续功能（如订阅生成、历史对比、自动淘汰）预留空间。


---

适用场景

Cloudflare 优选 IP 探测

VMess / VLESS / Trojan 节点入口筛选

Cloudflare Worker / Pages 反代入口

自动化订阅生成前置数据源

对 GitHub Actions / CI 出口网络进行真实测速


---

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)


仅供学习、研究与技术探索使用。

