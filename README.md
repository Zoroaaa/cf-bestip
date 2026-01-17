
CF IP Auto Selector

一个基于 GitHub Actions + Cloudflare cf-ray 的
Cloudflare IP 自动探测与筛选脚本。

该项目用于从 Cloudflare 官方 IP 段中随机抽取 IP，
通过请求指定的 Cloudflare Worker 域名，
获取实际接入的 POP 节点信息（cf-ray），
筛选出 当前 GitHub Actions 出口下可用、低延迟的 Cloudflare IP。




已实现功能

✅ 自动获取 Cloudflare 官方 IPv4 IP 段

✅ 随机抽样 IP 并进行并发探测

✅ 基于 cf-ray 判断实际接入的 Cloudflare POP

✅ 记录延迟并按延迟排序

✅ 生成 TXT / JSON 结果文件

✅ GitHub Actions 定时自动运行

✅ GitHub Pages 自动发布结果



---

License

MIT
仅供学习、研究与技术探索使用。

