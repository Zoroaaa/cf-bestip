# Cloudflare 优选 IP/代理IP 获取工具

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-Automated-green.svg)](https://github.com/features/actions)

**自动化 Cloudflare IPv4 Anycast IP 探测、测速、评分与区域归类工具**

[在线演示](https://zoroaaa.github.io/cf-bestip/) | [快速开始](#快速开始) | [配置说明](#配置说明) | [API 文档](#api-说明)

</div>

---

## 📑 目录

- [项目简介](#项目简介)
- [核心特性](#核心特性)
- [系统架构](#系统架构)
- [快速开始](#快速开始)
- [配置说明](#配置说明)
- [数据源](#数据源)
- [输出文件](#输出文件)
- [API 说明](#api-说明)
- [GitHub Actions 自动化](#github-actions-自动化)
- [项目结构](#项目结构)
- [技术细节](#技术细节)
- [常见问题](#常见问题)
- [许可证](#许可证)

---

## 🎯 项目简介

这是一个全自动化的 Cloudflare 优选 IP 和代理获取工具,通过智能扫描、多维度测试和 API 验证,为全球 12 个主要地区提供最优质的 Cloudflare IP 节点和代理服务器。

### 应用场景

- 🚀 CDN 加速优化
- 🔒 代理服务器部署
- 🌍 全球网络节点选择
- 📊 网络质量监控
- 🛡️ 安全隧道建立

---

## ✨ 核心特性

### 1. 多数据源聚合
- **Proxifly**: 支持 JSON 和 TXT 双格式
- **ProxyDaily**: 动态数据抓取
- **Tomcat1235**: HTML 表格解析
- **MonosansProxyList**: GitHub 仓库源

### 2. 智能 API 检测
- 🔍 自动代理可用性验证
- 🌐 实时地理位置识别
- ⏱️ 精确延迟测量
- 🔐 支持认证代理检测

### 3. 多地区支持
覆盖全球 **12 个主要地区**:

| 地区 | 代码 | 国旗 | 地区 | 代码 | 国旗 |
|------|------|------|------|------|------|
| 美国 | US | 🇺🇸 | 加拿大 | CA | 🇨🇦 |
| 英国 | GB | 🇬🇧 | 德国 | DE | 🇩🇪 |
| 法国 | FR | 🇫🇷 | 荷兰 | NL | 🇳🇱 |
| 意大利 | IT | 🇮🇹 | 俄罗斯 | RU | 🇷🇺 |
| 日本 | JP | 🇯🇵 | 新加坡 | SG | 🇸🇬 |
| 香港 | HK | 🇭🇰 | 印度 | IN | 🇮🇳 |

### 4. 协议支持
- ✅ **HTTPS** 代理
- ✅ **SOCKS5** 代理
- ✅ 带认证的代理
- ✅ 直连测试

### 5. 自动化部署
- 🤖 GitHub Actions 每日自动运行
- 📦 自动生成下载文件
- 🌐 自动部署到 GitHub Pages
- 📊 自动生成可视化报告

---

## 🏗️ 系统架构

```
┌─────────────────────────────────────────────────────────────┐
│                      GitHub Actions                          │
│                    (每日自动触发)                             │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                   内部测试模块                               │
│  • CF IP 段获取测试                                          │
│  • 数据源可用性测试                                          │
│  • API 连通性测试                                            │
│  • 代理连通性抽样测试                                        │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                   代理收集模块                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │  Proxifly   │  │ ProxyDaily  │  │ Tomcat1235  │        │
│  └─────────────┘  └─────────────┘  └─────────────┘        │
│  ┌─────────────┐                                            │
│  │  Monosans   │                                            │
│  └─────────────┘                                            │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                   API 检测模块                               │
│  • 发送 HTTP/SOCKS5 请求                                     │
│  • 测量延迟                                                  │
│  • 验证 HTTPS 支持                                           │
│  • 获取地理位置                                              │
│  • 提取认证信息                                              │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                   IP 扫描模块                                │
│  • 智能随机采样 Cloudflare IP                                │
│  • 并发代理测试                                              │
│  • 直连测试补充                                              │
│  • 多维度评分                                                │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                   结果输出模块                               │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │   TXT    │  │   JSON   │  │   HTML   │  │  GitHub  │   │
│  │  文件    │  │  数据    │  │  网页    │  │  Pages   │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## 🚀 快速开始

### 前置要求

- Python 3.11+
- curl 命令行工具
- Git

### 本地运行

```bash
# 1. 克隆仓库
git clone https://github.com/yourusername/cf-bestip.git
cd cf-bestip

# 2. 安装依赖
pip install -r requirements.txt

# 3. 运行内部测试
python -c "from tests import run_internal_tests; run_internal_tests()"

# 4. 开始扫描
python ip.py
```

### 输出位置

所有结果保存在 `public/` 目录:

```
public/
├── index.html              # 可视化网页
├── ip_all.txt              # 全部优选 IP
├── ip_[REGION].txt         # 各地区 IP
├── proxy_all.txt           # 全部代理列表
├── proxy_[REGION].txt      # 各地区代理
└── ip_candidates.json      # JSON 数据
```

---

## ⚙️ 配置说明

### 核心配置 (`config.py`)

```python
# 扫描参数
SAMPLE_SIZE_PER_REGION = 60      # 每个地区采样 IP 数量
TOTAL_SAMPLE = 720               # 总采样数
TIMEOUT = 15                     # 超时时间(秒)
MAX_WORKERS = 24                 # 并发线程数
LATENCY_LIMIT = 1300             # 延迟上限(毫秒)

# 代理测试参数
PROXY_TEST_TIMEOUT = 10          # 代理测试超时
PROXY_MAX_LATENCY = 1500         # HTTP 代理最大延迟
SOCKS5_MAX_LATENCY = 1500        # SOCKS5 代理最大延迟

# 输出限制
MAX_OUTPUT_PER_REGION = 6        # 每地区最多输出 IP 数
MAX_PROXIES_PER_REGION = 6       # 每地区最多输出代理数

# 代理检测 API
PROXY_CHECK_API_URL = "https://prcheck.ittool.pp.ua/check"
PROXY_CHECK_API_TOKEN = "your_token_here"

# 测试域名
TRACE_DOMAIN = "sptest.ittool.pp.ua"

# Cloudflare 端口
HTTPS_PORTS = [443, 8443, 2053, 2083, 2087, 2096]
```

### 地区映射

项目支持 **50+ 机场代码** 到地区的映射:

```python
COLO_MAP = {
    # 北美
    "YYZ": "CA", "LAX": "US", "SJC": "US", ...
    
    # 欧洲
    "LHR": "GB", "FRA": "DE", "CDG": "FR", ...
    
    # 亚太
    "HKG": "HK", "SIN": "SG", "NRT": "JP", ...
    
    # 更多...
}
```

---

## 📦 数据源

### 1. Proxifly
- **格式**: JSON / TXT
- **URL**: `https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/`
- **特点**: 高质量、更新频繁
- **支持协议**: HTTPS, SOCKS5

### 2. ProxyDaily
- **格式**: DataTables API (JSON)
- **URL**: `https://proxy-daily.com/api/serverside/proxies`
- **特点**: 实时数据、多字段信息
- **支持协议**: HTTPS, SOCKS5, SOCKS4

### 3. Tomcat1235
- **格式**: HTML 表格
- **URL**: `https://tomcat1235.nyc.mn/proxy_list`
- **特点**: 备用源、基础信息
- **需要**: BeautifulSoup 解析

### 4. MonosansProxyList
- **格式**: TXT (GitHub)
- **URL**: `https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt`
- **特点**: SOCKS5 专用、简洁格式

---

## 📄 输出文件

### 1. IP 列表文件 (TXT)

**格式**: `IP:端口#地区-分数`

```
104.21.45.123:443#US-score0.8567
172.67.123.45:2053#HK-score0.7891
```

**文件类型**:
- `ip_all.txt`: 全部地区 IP (按分数排序)
- `ip_US.txt`, `ip_HK.txt`, ...: 各地区 Top IP

### 2. 代理列表文件 (TXT)

**格式**:
- 无认证: `IP:端口#地区_延迟_来源`
- 有认证: `用户名:密码@IP:端口#地区_延迟_来源`

```
123.45.67.89:8080#US_234ms_proxifly
user:pass@98.76.54.32:1080#HK_456ms_proxydaily
```

**文件类型**:
- `proxy_all.txt`: 全部代理
- `proxy_US.txt`, `proxy_HK.txt`, ...: 各地区代理

### 3. JSON 数据 (`ip_candidates.json`)

```json
{
  "meta": {
    "generated_at": "2026-01-27T12:00:00Z",
    "total_nodes": 145,
    "total_proxies": 67,
    "regions": {
      "US": 23,
      "HK": 18,
      ...
    },
    "version": "2.1-single-domain",
    "test_domain": "sptest.ittool.pp.ua",
    "proxy_check_method": "api"
  },
  "nodes": [
    {
      "ip": "104.21.45.123",
      "port": 443,
      "region": "US",
      "colo": "LAX",
      "latencies": [234],
      "score": 0.8567
    },
    ...
  ]
}
```

### 4. HTML 网页 (`index.html`)

可视化界面包含:
- 📊 全局统计卡片
- 🗺️ 地区详情卡片
- 📥 分类下载按钮
- 🎨 响应式设计

---

## 🔌 API 说明

### 代理检测 API

**端点**: `https://prcheck.ittool.pp.ua/check`

**请求参数**:
```
GET /check?proxy=http://1.2.3.4:8080&token=YOUR_TOKEN
```

**响应格式**:
```json
{
  "success": true,
  "latency": 234,
  "https_ok": true,
  "location": {
    "country_code": "US",
    "city": "Los Angeles"
  },
  "username": "user",    // 如果需要认证
  "password": "pass"     // 如果需要认证
}
```

**集成示例**:
```python
from tests import check_proxy_with_api
from proxy_sources import ProxyInfo

proxy = ProxyInfo(
    host="1.2.3.4",
    port=8080,
    proxy_type="https"
)

result = check_proxy_with_api(proxy)
if result["success"]:
    print(f"延迟: {result['latency']}ms")
    print(f"国家: {result['country_code']}")
```

---

## 🤖 GitHub Actions 自动化

### 工作流程特性

- ⏰ **定时运行**: 每天 UTC 00:00 自动执行
- 🎯 **手动触发**: 支持 `workflow_dispatch`
- 🧪 **测试模式**: 可选仅运行内部测试
- 📦 **自动部署**: 结果自动推送到 GitHub Pages
- 🗑️ **清理机制**: 自动删除 7 天前的构建产物

### 配置 GitHub Actions

1. **启用 GitHub Pages**:
   - Settings → Pages → Source: `gh-pages` branch

2. **设置 Secrets** (可选):
   ```
   WEBSHARE_TOKEN: 你的代理服务令牌
   ```

3. **工作流文件**: `.github/workflows/run.yml`

### 运行日志示例

```
🔍 开始运行内部测试...
✅ 内部测试通过

🚀 开始执行多地区扫描...
============================================================
开始扫描地区: US
============================================================
使用 8 个代理进行扫描...
  → 通过代理 1.2.3.4:8080(https) 测试 60 个IP...
  ✓ 代理扫描收集: 42 条结果
============================================================
✓ US: 发现 23 个有效节点
============================================================

📊 扫描统计
============================================================
US  :  23 节点 |  8 代理 | 平均分数: 0.756
HK  :  18 节点 |  6 代理 | 平均分数: 0.689
...
============================================================
总代理数: 67
============================================================

✅ 扫描完成!
```

---

## 📁 项目结构

```
cf-bestip/
├── .github/
│   └── workflows/
│       └── run.yml              # GitHub Actions 工作流
├── config.py                    # 核心配置文件
├── ip.py                        # 主扫描脚本
├── proxy_sources.py             # 代理数据源模块
├── tests.py                     # 测试模块
├── template.html                # HTML 模板
├── requirements.txt             # Python 依赖
├── README.md                    # 项目文档
└── public/                      # 输出目录
    ├── index.html               # 生成的网页
    ├── ip_all.txt
    ├── proxy_all.txt
    ├── ip_candidates.json
    └── data/                    # 临时数据
```

---

## 🔬 技术细节

### 1. IP 评分算法

```python
def score_ip(latencies):
    """
    基于延迟的评分算法
    延迟越低,分数越高 (0-1 之间)
    """
    lat = latencies[0]
    score = 1 / (1 + lat / 200)
    return round(score, 4)
```

**评分标准**:
- 延迟 0ms → 分数 1.0000
- 延迟 200ms → 分数 0.5000
- 延迟 1000ms → 分数 0.1667

### 2. 智能采样策略

```python
def weighted_random_ips(cidrs, total):
    """
    按 CIDR 大小加权随机采样
    保证大网段有更多代表性
    """
    for net, weight in pools:
        cnt = max(1, int(total * weight / total_weight))
        result.extend(random.sample(hosts, min(cnt, len(hosts))))
    return result[:total]
```

### 3. 并发测试优化

- **代理测试**: 每个代理分配一组 IP,避免资源竞争
- **直连补充**: 当代理结果不足时自动触发直连测试
- **线程池**: 使用 `ThreadPoolExecutor` 实现高效并发
- **超时控制**: 多层超时机制防止挂起

### 4. 代理认证处理

```python
def get_proxy_url(self, protocol="http"):
    """
    自动构建代理 URL,支持认证
    """
    if self.api_result and self.api_result.get("username"):
        username = self.api_result["username"]
        password = self.api_result["password"]
        return f"{protocol}://{username}:{password}@{self.host}:{self.port}"
    else:
        return f"{protocol}://{self.host}:{self.port}"
```

### 5. COLO 识别机制

通过解析 `CF-Ray` 响应头:
```
CF-Ray: 8a1b2c3d4e5f6-LAX
                       ^^^
                     机场代码
```

---

## ❓ 常见问题

### 1. 为什么有些地区节点很少?

**原因**:
- Cloudflare 在该地区的 POP 点较少
- 代理质量不佳导致测试失败
- 网络波动影响测试结果

**解决方案**:
- 增加 `SAMPLE_SIZE_PER_REGION`
- 降低 `LATENCY_LIMIT` 标准
- 多次运行取平均值

### 2. 如何添加新的数据源?

1. 在 `proxy_sources.py` 中创建获取函数:
```python
def fetch_newsource_proxies(region):
    # 实现数据获取逻辑
    return proxies  # 返回 ProxyInfo 对象列表
```

2. 在 `ip.py` 的 `get_proxies()` 函数中添加调用:
```python
proxies.extend(fetch_newsource_proxies(region))
```

### 3. API 检测失败怎么办?

**检查清单**:
- ✅ API URL 是否正确
- ✅ Token 是否有效
- ✅ 网络连接是否正常
- ✅ API 是否有速率限制

**备选方案**:
- 使用其他代理检测 API
- 实现本地测试逻辑
- 降低并发请求数

### 4. GitHub Actions 运行失败?

**常见原因**:
1. **依赖安装失败**: 检查 `requirements.txt`
2. **权限不足**: 确保 Actions 有写权限
3. **超时**: 增加 `timeout-minutes`
4. **Pages 未启用**: 检查仓库设置

**调试方法**:
```bash
# 本地复现 Actions 环境
docker run -it ubuntu:latest
apt-get update && apt-get install -y python3 curl git
# 运行测试...
```

### 5. 如何自定义测试域名?

修改 `config.py`:
```python
TRACE_DOMAIN = "your-test-domain.com"
```

**注意**: 域名必须:
- 接入 Cloudflare
- 支持 HTTPS
- 返回 `CF-Ray` 头

---

## 📊 性能指标

### 典型运行时间

| 阶段 | 耗时 | 说明 |
|------|------|------|
| 内部测试 | 1-2 分钟 | 验证环境和数据源 |
| 代理收集 | 2-3 分钟 | 从多个源聚合代理 |
| IP 扫描 | 30-60 分钟 | 主要耗时阶段 |
| 结果生成 | <1 分钟 | 输出文件和网页 |
| **总计** | **35-65 分钟** | 取决于网络条件 |

### 资源消耗

- **内存**: ~500MB
- **CPU**: 中度使用 (多线程)
- **网络**: ~100-200 MB 下载/上传

---

## 🤝 贡献指南

欢迎提交 Issue 和 Pull Request!

### 开发流程

1. Fork 本仓库
2. 创建特性分支: `git checkout -b feature/AmazingFeature`
3. 提交更改: `git commit -m 'Add some AmazingFeature'`
4. 推送到分支: `git push origin feature/AmazingFeature`
5. 开启 Pull Request

### 代码规范

- 遵循 PEP 8 风格
- 添加必要的注释
- 更新相关文档
- 通过内部测试

---

## 📜 许可证

本项目采用 **MIT License** 开源协议。

```
MIT License

Copyright (c) 2026 Cloudflare IP Scanner

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 🌟 致谢

- Cloudflare 提供的优质 CDN 服务
- 各开源代理数据源项目
- GitHub Actions 自动化平台
- 所有贡献者和使用者

---

## 📮 联系方式

- **Issues**: [GitHub Issues](https://github.com/yourusername/cf-bestip/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/cf-bestip/discussions)

---

<div align="center">

**⚠️ 免责声明**

本项目仅供学习、研究与技术探索使用。  
使用本工具产生的任何后果由使用者自行承担。  
请遵守当地法律法规和 Cloudflare 服务条款。

---

Made with ❤️ by Cloudflare IP Scanner Team

**如果这个项目对你有帮助,请给个 ⭐️ Star!**

</div>
