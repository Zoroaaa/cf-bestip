# output_manager.py
import json
import os
from datetime import datetime
from config import OUTPUT_DIR
from html_generator import HTMLGenerator

class OutputManager:
    """输出管理器"""
    
    def __init__(self):
        self.output_dir = OUTPUT_DIR
        self.html_generator = HTMLGenerator()
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(f"{self.output_dir}/data", exist_ok=True)
    
    def save_results(self, all_nodes, region_results, region_proxies):
        """保存所有结果"""
        self._save_ip_files(all_nodes, region_results)
        self._save_proxy_files(region_proxies)
        self._save_json_file(all_nodes, region_results, region_proxies)
        self.html_generator.generate_html(all_nodes, region_results, region_proxies)
    
    def _save_ip_files(self, all_nodes, region_results):
        """保存IP文件"""
        # 保存总文件
        all_lines = [f'{n["ip"]}:{n["port"]}#{n["region"]}-score{n["score"]}\n' for n in all_nodes]
        
        with open(f"{self.output_dir}/ip_all.txt", "w") as f:
            f.writelines(all_lines)
        
        # 按地区保存
        for region, nodes in region_results.items():
            top_nodes = nodes[:6]  # MAX_OUTPUT_PER_REGION
            
            with open(f"{self.output_dir}/ip_{region}.txt", "w") as f:
                for n in top_nodes:
                    f.write(f'{n["ip"]}:{n["port"]}#{region}-score{n["score"]}\n')
        
        print(f"✓ 保存IP列表文件")
    
    def _save_proxy_files(self, region_proxies):
        """保存代理文件"""
        all_proxies_lines = []
        
        for region, proxies in region_proxies.items():
            for proxy in proxies:
                line = f"{proxy.host}:{proxy.port}#{region}_{proxy.tested_latency}ms_{proxy.source}\n"
                all_proxies_lines.append(line)
        
        # 保存总代理列表
        with open(f"{self.output_dir}/proxy_all.txt", "w") as f:
            f.writelines(all_proxies_lines)
        
        # 按地区保存
        for region, proxies in region_proxies.items():
            lines = []
            for proxy in proxies:
                line = f"{proxy.host}:{proxy.port}#{region}_{proxy.tested_latency}ms_{proxy.source}\n"
                lines.append(line)
            
            with open(f"{self.output_dir}/proxy_{region}.txt", "w") as f:
                f.writelines(lines)
        
        print(f"✓ 保存代理列表文件")
    
    def _save_json_file(self, all_nodes, region_results, region_proxies):
        """保存JSON文件"""
        with open(f"{self.output_dir}/ip_candidates.json", "w") as f:
            json.dump({
                "meta": {
                    "generated_at": datetime.utcnow().isoformat() + "Z",
                    "total_nodes": len(all_nodes),
                    "regions": {r: len(nodes) for r, nodes in region_results.items()},
                    "version": "2.0-api",
                    "data_sources": ["proxifly", "proxydaily", "tomcat1235"],
                    "protocols": ["https", "socks5"],
                    "proxy_check_method": "api",
                    "total_proxies": sum(len(proxies) for proxies in region_proxies.values())
                },
                "nodes": all_nodes[:200]
            }, f, indent=2)
        
        print(f"✓ 保存JSON文件")