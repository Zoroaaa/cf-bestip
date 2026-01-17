
CF IP Auto Selector

一个基于 Cloudflare Trace 机制 的自动化 IP 质量评估与筛选工具，
通过 多入口视角 + 延迟 + 稳定性评分模型，筛选出更真实、更稳定、更具实用价值的 Cloudflare 边缘 IP。

项目每日自动运行，并将结果发布至 GitHub Pages，适用于代理节点优选、网络质量评估等场景。


---

一、项目核心目标

传统 Cloudflare IP“测速优选”常见问题：

单入口测速，结果高度依赖路径

偶然命中快 IP，稳定性不可复现

POP 偏置严重，实际使用体验不一致


本项目的目标是解决这些问题：

> 用最小但充分的多视角观测，
过滤“假快 IP”，
输出可长期使用的稳定候选 IP。




---

二、核心设计思想

1️⃣ 多 Trace Domain（多入口视角）

项目使用 多个绑定至同一 Cloudflare Worker 的 trace_domain：

sptest.ittool.pp.ua
sptest1.ittool.pp.ua
sptest2.ittool.pp.ua

每个 domain 代表一个独立入口上下文，用于验证：

是否存在路径依赖

是否为单 POP 偶然快

是否具备跨入口稳定性


> 3 个视角是最小可判别集：
可以定位异常视角，而不过度增加采样成本。




---

2️⃣ Cloudflare Trace + cf-ray 解析

每次请求：

使用 curl --resolve 强制命中指定 IP

请求 Worker 返回的 Trace 页面

从 cf-ray 中提取 POP / Colo 信息


示例：

cf-ray: 7c1b9f8c9d2aHKG

解析得到：

Colo：HKG

Region：HK



---

3️⃣ 地区映射与白名单过滤

通过内置 COLO → Region 映射：

将 Cloudflare POP 转换为区域标签（HK / SG / JP / US 等）

仅输出关注地区的结果

避免低价值或不可控区域干扰结果



---

三、IP 评分模型（核心）

🎯 评分目标

> 综合评估一个 IP 在 多个入口视角下的真实性能与稳定性




---

1️⃣ 基础延迟评分（单视角）

对每个视角的延迟进行归一化处理：

LatencyScore = max(0, 1 - latency / LATENCY_LIMIT)

延迟越低，得分越高

超过阈值直接视为 0 分



---

2️⃣ 多视角聚合评分

对同一 IP 在多个 trace_domain 下的结果进行聚合：

AvgLatencyScore = mean(LatencyScore_v0, v1, v2)


---

3️⃣ 稳定性惩罚因子（关键）

如果同一 IP 在不同视角之间存在明显波动：

StabilityPenalty = 1 - (std(latencies) / LATENCY_LIMIT)

延迟越一致，惩罚越小

波动越大，整体评分被明显拉低



---

4️⃣ 最终 IP 评分公式

FinalScore = AvgLatencyScore × StabilityPenalty

评分范围：0 ~ 1

> 这是一个“偏保守”的评分模型
宁可错过偶然快 IP，也不放过不稳定 IP。




---

四、输出结果说明

1️⃣ 全量文本输出

public/ip_all.txt

格式：

IP:PORT#REGION-LATENCYms

示例：

162.159.192.10:443#HK-112ms


---

2️⃣ 按地区输出（限量）

public/ip_HK.txt
public/ip_SG.txt
public/ip_JP.txt
...

每个地区最多输出 MAX_OUTPUT_PER_REGION

已按评分 / 延迟排序



---

3️⃣ 全量 JSON 数据（分析用）

public/ip_all.json

包含字段：

{
  "ip": "162.159.x.x",
  "latency": 112,
  "colo": "HKG",
  "region": "HK",
  "score": 0.87,
  "views": {
    "v0": 108,
    "v1": 115,
    "v2": 113
  }
}

适用于：

二次分析

趋势统计

历史对比（后续扩展）



---

五、自动化运行机制

GitHub Actions

每日定时运行

手动触发支持

自动发布至 gh-pages


on:
  schedule:
    - cron: "0 3 * * *"
  workflow_dispatch:


---

六、项目适用场景

Cloudflare Worker / Argo Tunnel 出口优选

代理节点质量筛选

CF 边缘网络质量研究

网络路径稳定性分析



---

七、设计取向说明

❌ 不追求极限低延迟

❌ 不迷信单次测速

✅ 优先稳定性

✅ 优先可复现结果

✅ 优先工程可解释性



---

八、后续可扩展方向（规划）

多日历史评分（IP 生存周期）

自动淘汰机制

不同地区权重模型

并行 Worker 多入口 CI


---

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)


仅供学习、研究与技术探索使用。

