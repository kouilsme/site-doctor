# site-doctor

一条命令告诉你网站挂了到底是谁的锅。

不是又一个 ping 监控。Nezha、Uptime Kuma 会告诉你“红了”，site-doctor 告诉你“红在哪一层”：DNS、TCP、TLS、HTTP，还是源站和 CDN 之间。

## 用法

```bash
python3 site_doctor.py https://kouils.me
python3 site_doctor.py https://status.kouils.me --origin-ip 20.18.254.79
python3 site_doctor.py https://example.com --json
```

第一行永远是一句话结论，例如：

```
结论：源站死了：CDN 返回 502，直连源站也拿不到响应，CDN 只是把源站的错误透传回来，修源站，不是修 CDN。
```

后面是分项证据：DNS 耗时、解析 IP、TCP / TLS / TTFB、证书剩余天数、CDN 特征头、源站直连结果。

## 它能区分什么

| 判定 | 意思 |
| --- | --- |
| `DNS_FAIL` | 域名解析不到 IP，先查 DNS / 域名状态 |
| `TCP_FAIL` | 端口连不上，可能是防火墙 / 服务没起 |
| `TLS_FAIL` | 证书过期、不匹配或 TLS 配置问题 |
| `ORIGIN_DEAD` | 走 CDN 和直连源站都失败，源站死了 |
| `CDN_FAIL` | 源站直连是好的，走 CDN 失败，问题在 CDN 段 |
| `ORIGIN_5XX` | 源站返回 5xx（没给 `--origin-ip` 时按头信息推断） |
| `UP_WITH_WARNING` | 通的，但证书快过期或 DNS 很慢 |
| `UP` / `UP_BUT_4XX` | 通的；4xx 是这个 URL 本身的问题，不是全站挂 |

## 为什么加 `--origin-ip` 很重要

不加时，5xx 只能靠 CDN 响应头推断。给了源站真实 IP，工具会绕过 CDN 直连源站做一次同样的检查，两边一对比，是源站死还是 CDN 坏就基本确定了。

## 要求

- Python 3.8+，只用标准库，无第三方依赖
- 单文件，拷走就能跑：`site_doctor.py`

## 明确不做的事

第一版刻意不做：持续监控、告警推送、历史曲线、多节点对比、账号系统。这些是 Nezha / Uptime Kuma 已经做好的事，这个工具只做“挂了那一刻的一次诊断”。

## License

MIT
