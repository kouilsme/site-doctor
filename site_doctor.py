#!/usr/bin/env python3
"""
site-doctor: 一条命令告诉你网站挂了到底是谁的锅。

不是又一个 ping 监控。它只做一件事：对一个 URL 做一次分层诊断，
按 DNS -> TCP -> TLS -> HTTP -> CDN/源站 的顺序排查，最后先给一句话结论，
再给分项耗时和证据。

用法：
    python3 site_doctor.py https://kouils.me
    python3 site_doctor.py https://status.kouils.me --origin-ip 20.18.254.79
    python3 site_doctor.py https://example.com https://kouils.me
    python3 site_doctor.py https://example.com --json
    python3 site_doctor.py https://example.com --timeout 10

退出码：0 表示站是通的（包括带提醒、4xx），1 表示站挂了或诊断失败。
只用 Python 标准库，无第三方依赖，Python 3.8+ 可跑。
"""
import argparse
import json
import os
import socket
import ssl
import subprocess
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

VERSION = "0.2.0"

# 常见 CDN 的响应头特征，只做“提示”，不做绝对判定。
CDN_HINTS = [
    ("cf-ray", "Cloudflare"),
    ("cf-cache-status", "Cloudflare"),
    ("x-fastly-request-id", "Fastly"),
    ("fastly-debug-digest", "Fastly"),
    ("x-akamai-transformed", "Akamai"),
    ("akamai-cache-status", "Akamai"),
    ("x-vercel-id", "Vercel"),
    ("x-nf-request-id", "Netlify"),
    ("x-cache", "CDN cache header"),
    ("via", "proxy/CDN via header"),
]

# Cloudflare 5xx 代码本身就是“源站问题”的证据，不需要 --origin-ip 也能判定。
CF_CODES = {
    521: "源站直接拒绝了 Cloudflare 的连接（源站挂了或防火墙挡了 Cloudflare）",
    522: "Cloudflare 连源站超时（源站没响应或网络不通）",
    523: "Cloudflare 找不到源站（源站 IP / DNS 配错了）",
    524: "源站处理太慢，Cloudflare 等超时了",
    525: "Cloudflare 和源站的 TLS 握手失败（源站证书 / TLS 配置问题）",
    526: "源站证书无效，Cloudflare 拒绝继续（证书过期、不匹配或自签）",
}

DOWN_VERDICTS = {
    "DNS_FAIL", "TCP_FAIL", "TLS_FAIL", "HTTP_FAIL",
    "ORIGIN_DEAD", "ORIGIN_5XX", "CDN_FAIL", "REDIRECT_LOOP", "URL_INVALID",
}


def ms(start):
    return round((time.monotonic() - start) * 1000)


def detect_cdn_from_headers(headers):
    """headers: dict。返回 (cdn_name 或 '', 证据列表)。"""
    evidence = []
    name = ""
    lowered = {k.lower(): v for k, v in headers.items()}
    for key, label in CDN_HINTS:
        if key in lowered:
            evidence.append(f"{key}: {lowered[key]}")
            if label not in ("CDN cache header", "proxy/CDN via header") and not name:
                name = label
    server = lowered.get("server", "").lower()
    if "cloudflare" in server:
        name = "Cloudflare"
        evidence.append(f"server: {lowered.get('server', '')}")
    elif "vercel" in server:
        name = "Vercel"
    elif "github.com" in server:
        evidence.append(f"server: {lowered.get('server', '')}")
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
    """返回 (ips, dns_ms, error)。"""
    start = time.monotonic()
    try:
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            infos = socket.getaddrinfo(host, None)
        finally:
            socket.setdefaulttimeout(old)
        ips = sorted({info[4][0] for info in infos})
        return ips, ms(start), ""
    except Exception as e:
        return [], ms(start), str(e)


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


def http_get(sock, host, port, path, use_tls, timeout):
    """在已有连接上发一次 GET，返回 (status, headers, ttfb_ms, error)。"""
    import http.client

    start = time.monotonic()
    try:
        if use_tls:
            conn = http.client.HTTPSConnection(host, port, timeout=timeout)
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


def fetch_single(url, timeout):
    """对一个 URL 做一次 DNS + 主路径检查（不跟随重定向），返回中间结果。"""
    parsed = urlparse(url if "://" in url else "https://" + url)
    host = parsed.hostname
    if not host:
        return None, {"url": url, "host": "", "verdict": "URL_INVALID",
                      "conclusion": "URL 解析失败：给的地址里没有 hostname，先检查 URL 本身。"}
    scheme = parsed.scheme or "https"
    use_tls = scheme == "https"
    port = parsed.port or (443 if use_tls else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    ips, dns_ms, dns_err = resolve(host, timeout)
    out = {"url": url, "host": host, "port": port, "scheme": scheme,
           "dns_ms": dns_ms, "dns_error": dns_err, "ips": ips,
           "cname": dig_cname(host), "timeout": timeout}
    if not ips:
        out["verdict"] = "DNS_FAIL"
        out["conclusion"] = (
            f"DNS 解析失败：{host} 解析不到 IP（{dns_err}），"
            "先查 DNS / 域名状态 / 域名是否过期，这一步挂了，后面都不用查，"
            "不是源站也不是 CDN 的锅。"
        )
        return None, out
    main = check_via(ips[0], host, port, path, use_tls, timeout)
    out["main"] = main
    cdn_name, cdn_evidence = detect_cdn_from_headers(main["headers"])
    out["cdn_hint"] = cdn_name
    out["cdn_evidence"] = cdn_evidence
    return (host, port, path, use_tls, main, cdn_name), out


def diagnose(url, origin_ip="", timeout=10, cert_warn_days=14, max_redirects=5):
    """完整诊断：跟随重定向（最多 max_redirects 次），再做结论判定。"""
    current = url
    chain = []
    seen = set()
    fetch = None
    out = None
    for _ in range(max_redirects + 1):
        if current in seen:
            out = out or {"url": url, "host": "", "verdict": "REDIRECT_LOOP",
                          "conclusion": "重定向死循环：这个 URL 在几个地址之间来回跳，先查重定向规则。"}
            out["redirect_chain"] = chain
            return out
        seen.add(current)
        fetch, out = fetch_single(current, timeout)
        if fetch is None:
            out["redirect_chain"] = chain
            return out
        host, port, path, use_tls, main, cdn_name = fetch
        status = main["status"]
        lowered = {k.lower(): v for k, v in main["headers"].items()}
        location = lowered.get("location", "")
        if status in (301, 302, 303, 307, 308) and location:
            chain.append({"from": current, "status": status, "to": urljoin(current, location)})
            current = urljoin(current, location)
            continue
        break
    else:
        out["verdict"] = "REDIRECT_LOOP"
        out["conclusion"] = f"重定向次数超过 {max_redirects} 次还没到终点，先查重定向规则是不是写循环了。"
        out["redirect_chain"] = chain
        return out

    out["redirect_chain"] = chain
    out["origin_ip"] = origin_ip
    host, port, path, use_tls, main, cdn_name = fetch
    if chain:
        out["url"] = url  # 保持原始输入，终点放在 final_url
        out["final_url"] = current

    origin = None
    # 只有终点主机和原始主机一致时，源站直连对比才有意义。
    final_host = urlparse(current).hostname
    if origin_ip and final_host == urlparse(url if "://" in url else "https://" + url).hostname:
        origin = check_via(origin_ip, final_host, port, path, use_tls, timeout)
        out["origin"] = origin

    # ---- 结论判定，按“最先挂的那一层”优先 ----
    if main["tcp_error"]:
        if origin and not origin["tcp_error"] and origin["status"]:
            out["verdict"] = "CDN_FAIL"
            out["conclusion"] = (
                f"CDN / 边缘侧出问题：走 DNS 解析到的 {main['ip']} 连 TCP 都失败"
                f"（{main['tcp_error']}），但直连源站 {origin_ip} 能通，"
                "源站没死，问题在 CDN 到用户的这一段。"
            )
        else:
            out["verdict"] = "TCP_FAIL"
            out["conclusion"] = (
                f"TCP 连不上：{main['ip']}:{port} 拒绝 / 超时（{main['tcp_error']}），"
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
        # Cloudflare 代码本身就是证据，不用 --origin-ip 也能定位到源站。
        if status in CF_CODES and (cdn_name == "Cloudflare" or "cf-ray" in
                                   {k.lower() for k in main["headers"]}):
            if status in (525, 526):
                out["verdict"] = "TLS_FAIL"
            else:
                out["verdict"] = "ORIGIN_DEAD"
            out["conclusion"] = (
                f"Cloudflare 返回 {status}：{CF_CODES[status]}，"
                "CDN 本身在跑，问题在源站这一段，修源站，不是修 CDN。"
            )
            return out
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

    warnings = []
    if main["cert_days"] is not None and main["cert_days"] < cert_warn_days:
        warnings.append(f"证书 {main['cert_days']} 天后过期")
    if out["dns_ms"] > 2000:
        warnings.append(f"DNS 解析慢（{out['dns_ms']} ms）")
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
    redir_txt = f"，经过 {len(chain)} 次重定向" if chain else ""
    out["verdict"] = "UP"
    out["conclusion"] = (
        f"站是通的：HTTP {status}{cdn_txt}{redir_txt}，"
        "这次诊断没发现 DNS / TCP / TLS / HTTP 哪一层挂了。"
    )
    return out


def _color(text, code, use_color):
    if not use_color:
        return text
    return f"\033[{code}m{text}\033[0m"


def print_human(r, use_color=True):
    verdict = r["verdict"]
    if verdict in DOWN_VERDICTS:
        v_colored = _color(verdict, "31", use_color)  # 红
    elif verdict == "UP_WITH_WARNING":
        v_colored = _color(verdict, "33", use_color)  # 黄
    else:
        v_colored = _color(verdict, "32", use_color)  # 绿
    print(f"结论：{r['conclusion']}")
    print(f"判定：{v_colored}  |  目标：{r['url']}  |  主机：{r.get('host')}  |  DNS：{r.get('dns_ms')} ms")
    if r.get("final_url"):
        print(f"终点：{r['final_url']}")
    for step in r.get("redirect_chain") or []:
        print(f"重定向：{step['status']} {step['from']} -> {step['to']}")
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
    print("提示：加 --origin-ip <源站 IP> 能更确定是源站死还是 CDN 坏；Cloudflare 521-526 不用加也能定位到源站。")


def main(argv=None):
    ap = argparse.ArgumentParser(description="site-doctor: 网站挂了到底是谁的锅")
    ap.add_argument("urls", nargs="*", help="要诊断的 URL，例如 https://kouils.me（可给多个）")
    ap.add_argument("--origin-ip", default="", help="源站真实 IP，直连绕过 CDN 对比用")
    ap.add_argument("--timeout", type=float, default=10, help="每步超时秒数，默认 10")
    ap.add_argument("--cert-warn-days", type=int, default=14, help="证书剩余天数小于这个值就提醒，默认 14")
    ap.add_argument("--max-redirects", type=int, default=5, help="最多跟随几次重定向，默认 5")
    ap.add_argument("--json", action="store_true", help="输出 JSON，方便脚本调用")
    ap.add_argument("--no-color", action="store_true", help="关闭终端颜色")
    ap.add_argument("--version", action="store_true", help="打印版本")
    args = ap.parse_args(argv)
    if args.version:
        print(VERSION)
        return 0
    if not args.urls:
        ap.error("请至少给一个 URL，例如：python3 site_doctor.py https://kouils.me")
    use_color = (not args.no_color and "NO_COLOR" not in os.environ
                 and sys.stdout.isatty())
    results = []
    for url in args.urls:
        r = diagnose(url, args.origin_ip or "", args.timeout,
                     args.cert_warn_days, args.max_redirects)
        results.append(r)
        if not args.json:
            print_human(r, use_color)
            if len(args.urls) > 1:
                print("-" * 40)
    if args.json:
        payload = results[0] if len(results) == 1 else results
        print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
    # 退出码：只要有一个挂了就返回 1，方便脚本和 CI 判断。
    return 1 if any(r["verdict"] in DOWN_VERDICTS for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
