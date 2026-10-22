# site-doctor

一条命令告诉你网站挂了到底是谁的锅。

不是又一个 ping 监控。Nezha、Uptime Kuma 会告诉你“红了”，site-doctor 告诉你“红在哪一层”：DNS、TCP、TLS、HTTP，还是源站和 CDN 之间。

## 30 秒上手，不用安装

```bash
curl -O https://raw.githubusercontent.com/kouilsme/site-doctor/main/site_doctor.py
python3 site_doctor.py https://kouils.me
```

就这一个文件，Python 3.8+、只用标准库，不用 pip、不用账号、不用服务。

## 它会先给一句话结论

```text
结论：站是通的：HTTP 200，经 CDN：Fastly，这次诊断没发现 DNS / TCP / TLS / HTTP 哪一层挂了。
判定：UP  |  目标：https://kouils.me  |  主机：kouils.me  |  DNS：58 ms
解析 IP：185.199.108.153, 185.199.109.153, ...
主路径：TCP 1 ms / TLS 26 ms / 证书剩余 88 天 / HTTP 200 TTFB 200 ms
CDN 提示：Fastly（x-fastly-request-id: ...; via: 1.1 varnish; server: GitHub.com）
```

挂了的时候，结论会直接点名，例如“DNS 解析失败”“源站死了”“CDN 侧出问题”，后面再跟分项证据。

## 常用用法

```bash
# 一个站
python3 site_doctor.py https://example.com

# 一次查多个站
python3 site_doctor.py https://kouils.me https://example.com

# 有源站 IP 时，直连绕过 CDN 对比，源站死还是 CDN 坏基本能定死
python3 site_doctor.py https://status.kouils.me --origin-ip 20.18.254.79

# 给脚本用：JSON 输出 + 退出码（通了返回 0，挂了返回 1）
python3 site_doctor.py https://example.com --json
echo $?

# 证书快过期提醒的阈值，默认 14 天
python3 site_doctor.py https://example.com --cert-warn-days 30

# 不喜欢颜色，或输出要进日志
python3 site_doctor.py https://example.com --no-color
```

## 它能区分什么

| 判定 | 意思 |
| --- | --- |
| `DNS_FAIL` | 域名解析不到 IP，先查 DNS / 域名状态 |
| `TCP_FAIL` | 端口连不上，可能是防火墙 / 服务没起 |
| `TLS_FAIL` | 证书过期、不匹配或 TLS 配置问题 |
| `ORIGIN_DEAD` | 走 CDN 和直连源站都失败，源站死了；Cloudflare 521-524 不用给源站 IP 也能定到源站 |
| `CDN_FAIL` | 源站直连是好的，走 CDN 失败，问题在 CDN 段 |
| `ORIGIN_5XX` | 源站返回 5xx（没给 `--origin-ip` 且不是 Cloudflare 代码时，按头信息推断） |
| `REDIRECT_LOOP` | 重定向超过 5 次还没到终点，或来回跳 |
| `UP_WITH_WARNING` | 通的，但证书快过期或 DNS 很慢 |
| `UP` / `UP_BUT_4XX` | 通的；4xx 是这个 URL 本身的问题，不是全站挂 |

重定向会自动跟随，最多 5 次，链路会完整打印出来。

## 为什么加 `--origin-ip` 很重要

不加时，5xx 只能靠 CDN 响应头推断。给了源站真实 IP，工具会绕过 CDN 直连源站做一次同样的检查，两边一对比，是源站死还是 CDN 坏就基本确定了。例外：Cloudflare 的 521（源站拒绝连接）、522（连源站超时）、523（找不到源站）、524（源站太慢）、525/526（TLS / 证书问题）本身就是源站问题的证据，不用加也能定位。

## 明确不做的事

第一版刻意不做：持续监控、告警推送、历史曲线、多节点对比、账号系统、Web 界面。这些是 Nezha / Uptime Kuma 已经做好的事，这个工具只做“挂了那一刻的一次诊断”。

## 自己跑测试

测试全是离线的，只用本地 HTTP 服务器，不依赖外网：

```bash
python3 -m unittest discover -s tests -v
```

覆盖：UP、502、源站直连对比出的 CDN_FAIL、重定向跟随、Cloudflare 521、DNS 失败、TCP 拒绝、退出码。

## License

MIT
