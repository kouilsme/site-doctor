#!/usr/bin/env python3
"""
site-doctor: 一条命令告诉你网站挂了到底是谁的锅。

不是又一个 ping 监控。它只做一件事：对一个 URL 做一次分层诊断，
按 DNS -> TCP -> TLS -> HTTP -> CDN/源站 的顺序排查，最后先给一句话结论，
再给分项耗时和证据。

用法：
    python3 site_doctor.py https://kouils.me
    python3 site_doctor.py https://status.kouils.me --origin-ip 20.18.254.79
    python3 site_doctor.py https://example.com --json
    python3 site_doctor.py https://example.com --timeout 10

只用 Python 标准库，无第三方依赖，Python 3.8+ 可跑。
"""
import argparse
import json
import socket
import ssl
import subprocess
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

VERSION = "0.1.0"

# 常见 CDN 的响应头 / CNAME 特征，只做“提示”，不做绝对判定。
CDN_HINTS = [
    ("cf-ray", "Cloudflare"),
    ("cf-cache-status", "Cloudflare"),
    ("x-fastly-request-id", "Fastly"),
    ("fastly-debug-digest", "Fastly"),
    ("x-akamai-transformed", "Akamai"),
    ("akamai-cache-status", "Akamai"),
    ("x-cache", "CDN cache header"),
    ("via", "proxy/CDN via header"),
]


def ms(start):
    return round((time.monotonic() - start) * 1000)


def detect_cdn_from_headers(headers):
    """headers: dict, key 已转小写。返回 (cdn_name 或 '', 证据列表)。"""
    evidence = []
    name = ""
    lowered = {k.lower(): v for k, v in headers.items()}
    for key, label in CDN_HINTS:
        if key in lowered:
            evidence.append(f"{key}: {lowered[key]}")
            if label not in ("CDN cache header", "proxy/CDN via header") and not name:
                name = label
    server = lowered.get("server", "")
    if "cloudflare" in server.lower():
        name = "Cloudflare"
        evidence.append(f"server: {server}")
    if "github.com" in lowered.get("server", "").lower():
        evidence.append(f"server: {server}")
    return name, evidence


def dig_cname(host):
    """可选：用 dig 查 CNAME，dig 不存在或失败时静默返回空。"""
    try:
        out = subprocess.run(
            ["dig", "+short", "CNAME", host],
            capture_output=True, text=True, timeout=5,
        ).stdout.strip()
        return [line for line in out.splitlines() if line.strip()]
    except Exception:
        return []


def resolve(host, timeout):
    """返回 (ips, dns_ms, error, aliases)。"""
    start = time.monotonic()
    try:
        # getaddrinfo 会走系统 resolver，超时靠 socket 默认超时控制不了，
        # 这里用 setdefaulttimeout 包一层，跑完恢复。
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            infos = socket.getaddrinfo(host, None)
        finally:
            socket.setdefaulttimeout(old)
        ips = sorted({info[4][0] for info in infos})
        return ips, ms(start), "", []
    except Exception as e:
        return [], ms(start), str(e), []


def tcp_connect(ip, port, timeout):
    start = time.monotonic()
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        return sock, ms(start), ""
    except Exception as e:
        return None, ms(start), str(e)


def tls_info(sock, host, timeout):
    """在已有 TCP 连接上做 TLS 握手，返回 (ssl_sock, tls_ms, cert_days, error)。"""
    start = time.monotonic()
    ctx = ssl.create_default_context()
    try:
        ssock = ctx.wrap_socket(sock, server_hostname=host)
        cert = ssock.getpeercert()
        days = None
        if cert and "notAfter" in cert:
            exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            exp = exp.replace(tzinfo=timezone.utc)
            days = (exp - datetime.now(timezone.utc)).days
        return ssock, ms(start), days, ""
    except Exception as e:
        try:
            sock.close()
        except Exception:
            pass
        return None, ms(start), None, str(e)


def http_get(sock, host, port, path, use_tls, timeout, origin_ip=None):
    """在已有连接（TLS 或明文）上发一次 GET，返回 (status, headers, ttfb_ms, error)。"""
    import http.client

    start = time.monotonic()
    try:
        if use_tls:
            conn = http.client.HTTPSConnection(host, port, timeout=timeout)
            # 复用已握手的连接：把 socket 换成我们自己的
            conn.sock = sock
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
            conn.sock = sock
        conn.putrequest("GET", path or "/", skip_host=True, skip_accept_encoding=True)
        conn.putheader("Host", host)
        conn.putheader("User-Agent", f"site-doctor/{VERSION}")
        conn.putheader("Accept", "*/*")
        conn.putheader("Connection", "close")
        conn.endheaders()
        resp = conn.getresponse()
        ttfb = ms(start)
        # 只读一小段，确认能拿到 body 即可，不下载整个页面
        try:
            resp.read(4096)
        except Exception:
            pass
        headers = {k: v for k, v in resp.getheaders()}
        return resp.status, headers, ttfb, ""
    except Exception as e:
        return None, {}, ms(start), str(e)


def check_via(ip, host, port, path, use_tls, timeout):
    """对指定 IP 做一次 TCP (+TLS) + HTTP，返回分项结果 dict。"""
    result = {"ip": ip, "tcp_ms": None, "tcp_error": "",
              "tls_ms": None, "cert_days": None, "tls_error": "",
              "status": None, "headers": {}, "ttfb_ms": None, "http_error": ""}
    sock, tcp_ms, tcp_err = tcp_connect(ip, port, timeout)
    result["tcp_ms"] = tcp_ms
    result["tcp_error"] = tcp_err
    if sock is None:
        return result
    if use_tls:
        ssock, tls_ms, days, tls_err = tls_info(sock, host, timeout)
        result["tls_ms"] = tls_ms
        result["cert_days"] = days
        result["tls_error"] = tls_err
        if ssock is None:
            return result
        sock = ssock
    status, headers, ttfb, http_err = http_get(
        sock, host, port, path, use_tls, timeout)
    result["status"] = status
    result["headers"] = headers
    result["ttfb_ms"] = ttfb
    result["http_error"] = http_err
    try:
        sock.close()
    except Exception:
        pass
    return result


def diagnose(url, origin_ip, timeout):
    parsed = urlparse(url if "://" in url else "https://" + url)
    host = parsed.hostname
    if not host:
        return {"url": url, "host": "", "verdict": "URL_INVALID",
                "conclusion": "URL 解析失败：给的地址里没有 hostname，先检查 URL 本身。"}
    scheme = parsed.scheme or "https"
    use_tls = scheme == "https"
    port = parsed.port or (443 if use_tls else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    ips, dns_ms, dns_err, _ = resolve(host, timeout)
    cname = dig_cname(host)
    out = {
        "url": url, "host": host, "port": port, "scheme": scheme,
        "dns_ms": dns_ms, "dns_error": dns_err, "ips": ips, "cname": cname,
        "origin_ip": origin_ip, "timeout": timeout,
    }

    if not ips:
        out["verdict"] = "DNS_FAIL"
        out["conclusion"] = (
            f"DNS 解析失败：{host} 解析不到 IP（{dns_err}），"
            "先查 DNS / 域名状态 / 域名是否过期，这一步挂了，后面都不用查，"
            "不是源站也不是 CDN 的锅。"
        )
        return out

    main_ip = ips[0]
    main = check_via(main_ip, host, port, path, use_tls, timeout)
    out["main"] = main
    cdn_name, cdn_evidence = detect_cdn_from_headers(main["headers"])
    out["cdn_hint"] = cdn_name
    out["cdn_evidence"] = cdn_evidence

    origin = None
    if origin_ip:
        origin = check_via(origin_ip, host, port, path, use_tls, timeout)
        out["origin"] = origin

    # ---- 结论判定，按“最先挂的那一层”优先 ----
    if main["tcp_error"]:
        if origin and not origin["tcp_error"] and origin["status"]:
            out["verdict"] = "CDN_FAIL"
            out["conclusion"] = (
                f"CDN / 边缘侧出问题：走 DNS 解析到的 {main_ip} 连 TCP 都失败"
                f"（{main['tcp_error']}），但直连源站 {origin_ip} 能通，"
                "源站没死，问题在 CDN 到用户的这一段。"
            )
        else:
            out["verdict"] = "TCP_FAIL"
            out["conclusion"] = (
                f"TCP 连不上：{main_ip}:{port} 拒绝 / 超时（{main['tcp_error']}），"
                "可能是源站 / 边缘节点挂了，也可能是防火墙 / 安全组挡了端口，"
                "先确认端口和防火墙，再看服务本身。"
            )
        return out

    if use_tls and main["tls_error"]:
        out["verdict"] = "TLS_FAIL"
        out["conclusion"] = (
            f"TLS 握手失败：证书可能过期、域名和证书不匹配或 TLS 配置有问题"
            f"（{main['tls_error']}）。TCP 是通的，问题在证书 / TLS 这一层，"
            "先查证书有效期和域名。"
        )
        return out

    if main["status"] is None:
        if origin and origin["status"]:
            out["verdict"] = "CDN_FAIL"
            out["conclusion"] = (
                f"CDN 侧 HTTP 失败：直连源站 {origin_ip} 能返回 {origin['status']}，"
                f"但走 CDN 的请求失败（{main['http_error']}），问题在 CDN 这一段。"
            )
        elif origin and not origin["status"]:
            out["verdict"] = "ORIGIN_DEAD"
            out["conclusion"] = (
                "源站死了：走 CDN 和直连源站都拿不到 HTTP 响应，"
                f"CDN 侧错误：{main['http_error']}；源站侧错误：{origin['http_error']}。"
            )
        else:
            out["verdict"] = "HTTP_FAIL"
            out["conclusion"] = (
                f"HTTP 请求失败：TCP/TLS 都通，但拿不到响应（{main['http_error']}），"
                "可能是服务进程挂了、反代配错了或超时，先看源站服务日志。"
            )
        return out

    status = main["status"]
    if status >= 500:
        if origin and not origin["status"]:
            out["verdict"] = "ORIGIN_DEAD"
            out["conclusion"] = (
                f"源站死了：CDN 返回 {status}，直连源站 {origin_ip} 也拿不到响应，"
                "CDN 只是把源站的错误透传回来，修源站，不是修 CDN。"
            )
        elif origin and origin["status"] and origin["status"] < 500:
            out["verdict"] = "CDN_FAIL"
            out["conclusion"] = (
                f"CDN 侧出问题：源站直连返回 {origin['status']} 是好的，"
                f"但走 CDN 返回 {status}，问题在 CDN 配置 / 缓存 / 回源这一段。"
            )
        else:
            hint = f"（检测到 CDN 特征：{cdn_name}）" if cdn_name else "（未检测到常见 CDN 头，可能是直连源站）"
            out["verdict"] = "ORIGIN_5XX"
            out["conclusion"] = (
                f"源站返回 {status}：服务在跑但出错了{hint}，"
                "先看源站应用日志和 5xx 的具体路径；如果给了 --origin-ip，能更确定是源站还是 CDN。"
            )
        return out

    # 站是通的，但有值得提醒的亚健康
    warnings = []
    if main["cert_days"] is not None and main["cert_days"] < 14:
        warnings.append(f"证书 {main['cert_days']} 天后过期")
    if dns_ms > 2000:
        warnings.append(f"DNS 解析慢（{dns_ms} ms）")
    if warnings:
        out["verdict"] = "UP_WITH_WARNING"
        out["conclusion"] = (
            f"站是通的（HTTP {status}），但有提醒：{'、'.join(warnings)}，"
            "现在不用救火，但该排期处理了。"
        )
        return out

    if 400 <= status < 500:
        out["verdict"] = "UP_BUT_4XX"
        out["conclusion"] = (
            f"站本身是通的，但这个 URL 返回 {status}，"
            "不是全站挂了，先检查路径 / 权限 / 这个页面本身。"
        )
        return out

    cdn_txt = f"，经 CDN：{cdn_name}" if cdn_name else "，未检测到常见 CDN 头，可能是直连源站"
    out["verdict"] = "UP"
    out["conclusion"] = (
        f"站是通的：HTTP {status}{cdn_txt}，"
        "这次诊断没发现 DNS / TCP / TLS / HTTP 哪一层挂了。"
    )
    return out


def print_human(r):
    print(f"结论：{r['conclusion']}")
    print(f"判定：{r['verdict']}  |  目标：{r['url']}  |  主机：{r.get('host')}  |  DNS：{r.get('dns_ms')} ms")
    if r.get("ips"):
        print(f"解析 IP：{', '.join(r['ips'])}")
    if r.get("cname"):
        print(f"CNAME：{', '.join(r['cname'])}")
    m = r.get("main")
    if m:
        print(f"主路径：TCP {m['tcp_ms']} ms"
              + (f" / TLS {m['tls_ms']} ms" if m["tls_ms"] is not None else "")
              + (f" / 证书剩余 {m['cert_days']} 天" if m["cert_days"] is not None else "")
              + (f" / HTTP {m['status']} TTFB {m['ttfb_ms']} ms" if m["status"] else ""))
        if m["tcp_error"]:
            print(f"  TCP 错误：{m['tcp_error']}")
        if m["tls_error"]:
            print(f"  TLS 错误：{m['tls_error']}")
        if m["http_error"]:
            print(f"  HTTP 错误：{m['http_error']}")
    if r.get("cdn_hint") or r.get("cdn_evidence"):
        print(f"CDN 提示：{r.get('cdn_hint') or '未确定'}"
              + (f"（{'; '.join(r['cdn_evidence'])}）" if r.get("cdn_evidence") else ""))
    o = r.get("origin")
    if o:
        if o["status"]:
            print(f"源站直连（{r['origin_ip']}）：HTTP {o['status']} TTFB {o['ttfb_ms']} ms")
        else:
            errs = "; ".join(f"{k}:{v}" for k, v in
                             [("TCP", o["tcp_error"]), ("TLS", o["tls_error"]), ("HTTP", o["http_error"])] if v)
            print(f"源站直连（{r['origin_ip']}）：失败（{errs or '未知错误'}）")
    print("提示：加 --origin-ip <源站 IP> 能更确定是源站死还是 CDN 坏；不加时 5xx 只能按头信息推断。")


def main(argv=None):
    ap = argparse.ArgumentParser(description="site-doctor: 网站挂了到底是谁的锅")
    ap.add_argument("url", help="要诊断的 URL，例如 https://kouils.me")
    ap.add_argument("--origin-ip", default="", help="源站真实 IP，直连绕过 CDN 对比用")
    ap.add_argument("--timeout", type=float, default=10, help="每步超时秒数，默认 10")
    ap.add_argument("--json", action="store_true", help="输出 JSON，方便脚本调用")
    ap.add_argument("--version", action="store_true", help="打印版本")
    args = ap.parse_args(argv)
    if args.version:
        print(VERSION)
        return 0
    r = diagnose(args.url, args.origin_ip or "", args.timeout)
    if args.json:
        print(json.dumps(r, ensure_ascii=False, indent=2, default=str))
    else:
        print_human(r)
    return 0


if __name__ == "__main__":
    sys.exit(main())
