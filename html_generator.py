# html_generator.py
from datetime import datetime
from config import OUTPUT_DIR, MAX_OUTPUT_PER_REGION

class HTMLGenerator:
    """HTML页面生成器"""
    
    def __init__(self):
        self.output_dir = OUTPUT_DIR
    
    def generate_html(self, all_nodes, region_results, region_proxies):
        """生成完整的HTML页面"""
        template = self._load_html_template()
        html_content = self._render_template(template, all_nodes, region_results, region_proxies)
        
        with open(f"{self.output_dir}/index.html", "w", encoding="utf-8") as f:
            f.write(html_content)
        
        print(f"✓ 生成HTML页面: {self.output_dir}/index.html")
    
    def _load_html_template(self):
        """加载HTML模板"""
        return """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cloudflare IP 优选</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'PingFang SC', 'Microsoft YaHei', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        .header {
            text-align: center;
            color: white;
            margin-bottom: 30px;
        }
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }
        .header .subtitle {
            font-size: 1em;
            opacity: 0.95;
            margin-bottom: 5px;
        }
        .header .meta {
            font-size: 0.85em;
            opacity: 0.85;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            text-align: center;
        }
        .stat-card h3 {
            color: #667eea;
            font-size: 0.9em;
            margin-bottom: 12px;
            font-weight: 600;
        }
        .stat-card .value {
            font-size: 2.5em;
            font-weight: bold;
            color: #333;
        }
        .stat-card .update-time {
            margin-top: 8px;
            font-size: 0.75em;
            color: #718096;
        }
        .download-section {
            background: white;
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }
        .download-section h2 {
            color: #333;
            font-size: 1.3em;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .download-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }
        .download-btn {
            padding: 15px 20px;
            border: none;
            border-radius: 8px;
            font-size: 0.95em;
            cursor: pointer;
            text-decoration: none;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            transition: all 0.3s;
            font-weight: 500;
            text-align: center;
        }
        .download-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 12px rgba(0,0,0,0.15);
        }
        .btn-primary {
            background: #667eea;
            color: white;
        }
        .btn-primary:hover {
            background: #5568d3;
        }
        .btn-success {
            background: #48bb78;
            color: white;
        }
        .btn-success:hover {
            background: #38a169;
        }
        .btn-info {
            background: #4299e1;
            color: white;
        }
        .btn-info:hover {
            background: #3182ce;
        }
        .btn-warning {
            background: #ed8936;
            color: white;
        }
        .btn-warning:hover {
            background: #dd7724;
        }
        .region-section {
            margin-bottom: 30px;
        }
        .region-section h2 {
            color: white;
            font-size: 1.5em;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .region-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 20px;
        }
        .region-card {
            background: white;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: transform 0.3s, box-shadow 0.3s;
        }
        .region-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 16px rgba(0,0,0,0.15);
        }
        .region-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 18px 20px;
            font-size: 1.2em;
            font-weight: bold;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .region-count {
            font-size: 0.8em;
            opacity: 0.9;
        }
        .region-body {
            padding: 20px;
        }
        .ip-list {
            margin-bottom: 15px;
        }
        .ip-item {
            padding: 12px;
            margin-bottom: 10px;
            background: #f7fafc;
            border-radius: 8px;
            border-left: 4px solid #667eea;
            transition: background 0.2s;
        }
        .ip-item:hover {
            background: #edf2f7;
        }
        .ip-item:last-child {
            margin-bottom: 0;
        }
        .ip-address {
            font-family: 'Courier New', 'Consolas', monospace;
            font-size: 1.05em;
            color: #2d3748;
            margin-bottom: 6px;
            font-weight: 600;
        }
        .ip-meta {
            font-size: 0.85em;
            color: #718096;
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }
        .badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: 500;
        }
        .badge-score {
            background: #48bb78;
            color: white;
        }
        .badge-latency {
            background: #4299e1;
            color: white;
        }
        .badge-colo {
            background: #ed8936;
            color: white;
        }
        .region-downloads {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
            margin-top: 15px;
        }
        .region-download-btn {
            padding: 10px 15px;
            border: none;
            border-radius: 6px;
            font-size: 0.9em;
            cursor: pointer;
            text-decoration: none;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
            transition: all 0.3s;
            font-weight: 500;
        }
        .region-download-btn:hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.15);
        }
        .proxy-section {
            background: white;
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }
        .proxy-section h2 {
            color: #333;
            font-size: 1.3em;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .proxy-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 15px;
        }
        .proxy-card {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 15px;
            border-left: 4px solid #48bb78;
        }
        .proxy-card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        .proxy-region {
            font-weight: bold;
            color: #2d3748;
        }
        .proxy-count {
            font-size: 0.8em;
            color: #718096;
        }
        .proxy-list {
            max-height: 120px;
            overflow-y: auto;
        }
        .proxy-item {
            padding: 8px;
            margin-bottom: 5px;
            background: white;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .proxy-item:last-child {
            margin-bottom: 0;
        }
        .proxy-address {
            color: #2d3748;
        }
        .proxy-meta {
            font-size: 0.75em;
            color: #718096;
            display: flex;
            gap: 5px;
        }
        .proxy-downloads {
            margin-top: 10px;
            display: flex;
            gap: 10px;
        }
        .proxy-download-btn {
            padding: 8px 12px;
            border: none;
            border-radius: 4px;
            font-size: 0.8em;
            cursor: pointer;
            text-decoration: none;
            display: flex;
            align-items: center;
            gap: 4px;
            transition: all 0.3s;
        }
        .footer {
            text-align: center;
            color: white;
            margin-top: 40px;
            padding: 20px;
            opacity: 0.9;
        }
        .footer p {
            margin: 5px 0;
        }
        @media (max-width: 768px) {
            .header h1 {
                font-size: 1.8em;
            }
            .stats-grid {
                grid-template-columns: 1fr;
            }
            .download-grid {
                grid-template-columns: 1fr;
            }
            .region-grid {
                grid-template-columns: 1fr;
            }
            .region-downloads {
                grid-template-columns: 1fr;
            }
            .proxy-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🌐 Cloudflare IP 优选</h1>
            <div class="subtitle">多数据源 | HTTPS + SOCKS5 | API智能检测</div>
            <div class="meta">更新时间: {{GENERATED_TIME}}</div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <h3>总节点数</h3>
                <div class="value">{{TOTAL_NODES}}</div>
            </div>
            <div class="stat-card">
                <h3>数据源</h3>
                <div class="value">{{TOTAL_REGIONS}}</div>
            </div>
            <div class="stat-card">
                <h3>可用代理</h3>
                <div class="value">{{TOTAL_PROXIES}}</div>
            </div>
        </div>

        <div class="download-section">
            <h2>📦 下载文件</h2>
            <div class="download-grid">
                <a href="ip_all.txt" class="download-btn btn-primary" download>
                    🌍 全部IP列表
                </a>
                <a href="proxy_all.txt" class="download-btn btn-success" download>
                    🔑 全部代理列表
                </a>
                <a href="ip_candidates.json" class="download-btn btn-info" download>
                    📄 JSON数据
                </a>
            </div>
        </div>

        <!-- 新增代理信息展示区域 -->
        <div class="proxy-section">
            <h2>🔑 可用代理列表</h2>
            <div class="proxy-grid">
                {{PROXY_CARDS}}
            </div>
        </div>

        <div class="region-section">
            <h2>🗺️ Top 50 节点</h2>
            <div class="region-grid">
                {{REGION_CARDS}}
            </div>
        </div>

        <div class="footer">
            <p><strong>Powered by Cloudflare IP Scanner V2.0 API Edition</strong></p>
            <p>🚀 多数据源聚合 | 智能API检测 | 自动化测试</p>
        </div>
    </div>
</body>
</html>"""
    
    def _render_template(self, template, all_nodes, region_results, region_proxies):
        """渲染模板"""
        # 生成地区卡片
        region_cards_html = []
        
        for region in sorted(region_results.keys()):
            nodes = region_results[region]
            if not nodes:
                continue
            
            # 每个地区的IP列表
            ip_items_html = []
            for node in nodes[:MAX_OUTPUT_PER_REGION]:
                min_latency = min(node['latencies'])
                ip_html = f"""
                <div class="ip-item">
                    <div class="ip-address">{node['ip']}:{node['port']}</div>
                    <div class="ip-meta">
                        <span class="badge badge-score">分数 {node['score']}</span>
                        <span class="badge badge-latency">延迟 {min_latency}ms</span>
                        <span class="badge badge-colo">COLO {node['colo']}</span>
                    </div>
                </div>"""
                ip_items_html.append(ip_html)
            
            # 地区卡片
            card_html = f"""
            <div class="region-card">
                <div class="region-header">
                    <span>{region}</span>
                    <span class="region-count">{len(nodes)} 节点</span>
                </div>
                <div class="region-body">
                    <div class="ip-list">
                        {''.join(ip_items_html)}
                    </div>
                    <div class="region-downloads">
                        <a href="ip_{region}.txt" class="region-download-btn btn-primary" download>
                            📥 IP列表
                        </a>
                        <a href="proxy_{region}.txt" class="region-download-btn btn-success" download>
                            🔑 代理列表
                        </a>
                    </div>
                </div>
            </div>"""
            region_cards_html.append(card_html)
        
        # 生成代理卡片
        proxy_cards_html = []
        for region in sorted(region_proxies.keys()):
            proxies = region_proxies[region]
            if not proxies:
                continue
            
            # 代理列表
            proxy_items_html = []
            for proxy in proxies[:5]:  # 显示前5个代理
                proxy_html = f"""
                <div class="proxy-item">
                    <div class="proxy-address">{proxy.host}:{proxy.port}</div>
                    <div class="proxy-meta">
                        <span>{proxy.type.upper()}</span>
                        <span>{proxy.tested_latency}ms</span>
                    </div>
                </div>"""
                proxy_items_html.append(proxy_html)
            
            # 代理卡片
            proxy_card_html = f"""
            <div class="proxy-card">
                <div class="proxy-card-header">
                    <span class="proxy-region">{region}</span>
                    <span class="proxy-count">{len(proxies)} 代理</span>
                </div>
                <div class="proxy-list">
                    {''.join(proxy_items_html)}
                </div>
                <div class="proxy-downloads">
                    <a href="proxy_{region}.txt" class="proxy-download-btn btn-success" download>
                        📥 下载代理
                    </a>
                </div>
            </div>"""
            proxy_cards_html.append(proxy_card_html)
        
        # 统计信息
        total_proxies = sum(len(proxies) for proxies in region_proxies.values())
        
        # 替换模板变量
        html_content = template.replace('{{GENERATED_TIME}}', datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'))
        html_content = html_content.replace('{{TOTAL_NODES}}', str(len(all_nodes)))
        html_content = html_content.replace('{{TOTAL_REGIONS}}', str(len(region_results)))
        html_content = html_content.replace('{{TOTAL_PROXIES}}', str(total_proxies))
        html_content = html_content.replace('{{REGION_CARDS}}', '\n'.join(region_cards_html))
        html_content = html_content.replace('{{PROXY_CARDS}}', '\n'.join(proxy_cards_html) if proxy_cards_html else '<p>暂无可用代理</p>')
        
        return html_content
