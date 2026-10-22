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

# 有源站 IP 时，直连绕过 CDN 对比，辅助定位源站或 CDN 链路问题
python3 site_doctor.py https://status.kouils.me --origin-ip 20.18.254.79

# 给脚本用：JSON 输出 + 退出码（通了返回 0，挂了返回 1）
python3 site_doctor.py https://example.com --json
echo $?

# 证书快过期提醒的阈值，默认 14 天
python3 site_doctor.py https://example.com --cert-warn-days 30

# 不喜欢颜色，或输出要进日志
python3 site_doctor.py https://example.com --no-color
```

`--timeout` 是每次网络操作的超时，不是整次诊断的总时限；多 IP 回退、重定向、源站对比会累加耗时。

## 它能区分什么

| 判定 | 意思 |
| --- | --- |
| `DNS_FAIL` | 域名解析不到 IP，先查 DNS / 域名状态 |
| `TCP_FAIL` | 端口连不上，可能是防火墙 / 服务没起 |
| `TLS_FAIL` | 证书过期、不匹配或 TLS 配置问题 |
| `ORIGIN_DEAD` | 源站或回源链路异常；直连失败也可能是防火墙限制，需结合日志确认 |
| `CDN_FAIL` | 源站直连是好的，走 CDN 失败，问题在 CDN 段 |
| `ORIGIN_5XX` | HTTP 返回 5xx；保留原判定名，但仅凭响应头不能确定是源站还是 CDN 生成 |
| `REDIRECT_LOOP` | 重定向超过 5 次还没到终点，或来回跳 |
| `UP_WITH_WARNING` | 通的，但证书快过期、DNS 很慢，或部分 IP 失败后回退成功 |
| `UP` / `UP_BUT_4XX` | 通的；4xx 是这个 URL 本身的问题，不是全站挂 |
| `HTTP_FAIL` | TCP / TLS 已通，但无法获取 HTTP 响应头 |
| `URL_INVALID` | URL 或重定向目标无效，包括不支持的协议、非法端口 |

重定向会自动跟随，最多 5 次，链路会完整打印出来。

## 为什么加 `--origin-ip` 很重要

不加时，5xx 只能靠 CDN 响应头推断。给了源站真实 IP，工具会保留目标域名的 Host / TLS SNI，绕过 CDN 直连源站做一次同样的检查。两边对比可以缩小排查范围，但源站仅允许 CDN IP、使用私有 CA 或限制访问时，直连失败不代表源站宕机。跨域重定向后不会把原源站 IP 用到新域名上。

Cloudflare 的 521（源站拒绝连接）、522（连源站超时）、523（找不到源站）、524（源站太慢）、525/526（TLS / 证书问题）可以指向回源链路，需要继续检查源站服务、CDN 回源配置和中间网络。
