#!/usr/bin/env python3
"""Resolve server domains in proxy links to IPs; leave everything else alone.

Companion to semantic_deduplicate.py. For each input line:
  - not a link              -> passed through unchanged
  - endpoint already an IP  -> passed through unchanged
  - endpoint is a domain    -> resolved; line rewritten with the IP
  - domain fails to resolve -> line passed through unchanged (warned with -v)

Link count is preserved 1:1. Supported: vmess, ss (SIP002 + legacy), ssr,
and generic URIs (vless, trojan, hysteria2/hy2, tuic, ...).

Usage:
    python resolve_hosts.py all_dd.txt -o resolved.txt
    python resolve_hosts.py all_dd.txt --family any --workers 100 -v
    cat links.txt | python resolve_hosts.py - > resolved.txt
    python resolve_hosts.py --self-test
"""
from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlsplit, urlunsplit

__all__ = ["parse_line", "resolve_host", "resolve_lines", "main"]


# --------------------------------------------------------------------------
# base64 / small helpers
# --------------------------------------------------------------------------

def _b64decode(data: str) -> bytes:
    """Decode standard or URL-safe base64, tolerating missing padding."""
    data = data.strip().replace("-", "+").replace("_", "/")
    data += "=" * (-len(data) % 4)
    if not data.isascii():
        raise ValueError("payload contains non-ASCII characters (not base64)")
    return base64.b64decode(data, validate=False)


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip().strip("[]"))
        return True
    except ValueError:
        return False


def _wrap(host: str) -> str:
    """Bracket an IPv6 literal so it is safe inside a netloc."""
    return f"[{host}]" if ":" in host and not host.startswith("[") else host


def _split_hostport(hostport: str) -> tuple:
    """'host:port' / '[v6]:port' -> (host, ':port' or '')."""
    hostport = hostport.strip()
    if hostport.startswith("["):
        host, _, rest = hostport[1:].partition("]")
        return host, rest
    host, sep, port = hostport.rpartition(":")
    if sep and port.isdigit():
        return host, ":" + port
    return hostport, ""


# --------------------------------------------------------------------------
# Per-scheme parsing: each returns (host, rebuild) or None.
# rebuild(ip) -> the full line with the host replaced (never mutates input).
# --------------------------------------------------------------------------

def _parse_vmess(line: str):
    _, _, payload = line.partition("://")
    frag = ""
    if "#" in payload:
        payload, _, frag = payload.partition("#")
    payload = payload.split("?", 1)[0]
    try:
        obj = json.loads(_b64decode(payload).decode("utf-8", "replace"))
    except Exception:
        return None
    if not isinstance(obj, dict):
        return None
    host = str(obj.get("add", "")).strip()
    if not host:
        return None

    def rebuild(ip: str) -> str:
        obj2 = dict(obj)
        obj2["add"] = ip
        data = json.dumps(obj2, ensure_ascii=False, separators=(",", ":")).encode()
        out = "vmess://" + _b64encode(data)
        return out + ("#" + frag if frag else "")

    return host, rebuild


def _parse_ss(line: str):
    _, _, body = line.partition("://")
    frag = ""
    if "#" in body:
        body, _, frag = body.partition("#")
    query = ""
    if "?" in body:
        body, _, query = body.partition("?")

    if "@" in body:  # SIP002
        userinfo, _, hostport = body.rpartition("@")
        host, rest = _split_hostport(hostport)
        if not host:
            return None

        def rebuild(ip: str) -> str:
            out = f"ss://{userinfo}@{_wrap(ip)}{rest}"
            if query:
                out += "?" + query
            return out + ("#" + frag if frag else "")

        return host, rebuild

    # legacy: the whole payload is base64(method:password@host:port)
    try:
        decoded = _b64decode(body).decode("utf-8", "replace")
    except Exception:
        return None
    cred, _, hostport = decoded.rpartition("@")
    if not cred:
        return None
    host, rest = _split_hostport(hostport)
    if not host:
        return None

    def rebuild(ip: str) -> str:
        payload = _b64encode(f"{cred}@{_wrap(ip)}{rest}".encode())
        return "ss://" + payload + ("#" + frag if frag else "")

    return host, rebuild


def _parse_ssr(line: str):
    _, _, payload = line.partition("://")
    frag = ""
    if "#" in payload:
        payload, _, frag = payload.partition("#")
    try:
        decoded = _b64decode(payload.split("/?", 1)[0]).decode("utf-8", "replace")
    except Exception:
        return None
    main = decoded.split("/?", 1)[0]

    if main.startswith("["):  # bracketed IPv6
        host, _, rest = main[1:].partition("]")
        if not host or not rest.startswith(":"):
            return None

        def rebuild(ip: str) -> str:
            out = "ssr://" + _b64encode(f"[{ip}]{rest}".encode())
            return out + ("#" + frag if frag else "")

        return host, rebuild

    parts = main.rsplit(":", 5)  # host:port:proto:method:obfs:b64pass
    if len(parts) != 6 or not parts[1].isdigit():
        return None
    host, tail = parts[0], parts[1:]

    def rebuild(ip: str) -> str:
        out = "ssr://" + _b64encode(":".join([ip] + tail).encode())
        return out + ("#" + frag if frag else "")

    return host, rebuild


def _parse_generic(line: str):
    try:
        parts = urlsplit(line)
    except ValueError:
        return None
    host = parts.hostname  # lowercased, unbracketed
    if not host:
        return None
    userinfo, at, hostport = parts.netloc.rpartition("@")

    # Keep whatever follows the host in the netloc verbatim (':443', ':8443', ...)
    if hostport.lower().startswith(host.lower()):
        rest = hostport[len(host):]
    else:  # bracketed original host
        _, sep, port = hostport.rpartition(":")
        rest = ":" + port if sep and port.isdigit() else ""

    def rebuild(ip: str):
        netloc = (userinfo + "@" if at else "") + _wrap(ip) + rest
        try:
            return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
        except ValueError:
            return None

    return host, rebuild


def parse_line(line: str):
    """Parse one line -> (endpoint_host, rebuild(ip)) or None if not a link."""
    if "://" not in line:
        return None
    scheme = line.split("://", 1)[0].strip().lower()
    parser = {"vmess": _parse_vmess, "ss": _parse_ss, "ssr": _parse_ssr}.get(scheme, _parse_generic)
    try:
        return parser(line)
    except Exception:
        return None


# --------------------------------------------------------------------------
# Resolution
# --------------------------------------------------------------------------

def resolve_host(host: str, family: str = "4"):
    """Resolve a domain to one IP, or None. 'family': 4, 6, or any (v4 preferred)."""
    name = host.strip().strip("[].").lower()
    flag = {"4": socket.AF_INET, "6": socket.AF_INET6, "any": socket.AF_UNSPEC}.get(family, socket.AF_INET)
    try:
        infos = socket.getaddrinfo(name, None, family=flag, type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError):
        return None
    if family == "any":
        infos = sorted(infos, key=lambda i: i[0] != socket.AF_INET)  # v4 first
    return infos[0][4][0] if infos else None


def _resolve_all(hosts, resolver, workers: int, verbose: bool) -> dict:
    mapping = {}
    hosts = list(hosts)
    if not hosts:
        return mapping
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(hosts)))) as pool:
        futures = {pool.submit(resolver, h): h for h in hosts}
        for fut in as_completed(futures):
            host = futures[fut]
            try:
                ip = fut.result()
            except Exception as exc:
                ip = None
                if verbose:
                    print(f"[!] {host}: resolver error: {exc}", file=sys.stderr)
            if ip:
                mapping[host] = ip
            elif verbose:
                print(f"[!] could not resolve {host} (line left unchanged)", file=sys.stderr)
    return mapping


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def _normalize_lines(lines):
    """Accept a str, file-like object, or iterable of lines/multi-line chunks."""
    if isinstance(lines, str):
        return lines.splitlines()
    out = []
    for item in lines:
        if hasattr(item, "read"):
            out.extend(item.read().splitlines())
        elif isinstance(item, str):
            out.extend(item.splitlines())  # splits 1-line items trivially
        else:
            raise TypeError(f"expected str or file-like, got {type(item).__name__}")
    return out


def resolve_lines(lines, *, family: str = "4", workers: int = 50,
                  resolver=None, verbose: bool = False):
    """Resolve domains in proxy links. Returns (new_lines, stats).

    new_lines has exactly the same length as the input. Lines whose endpoint
    is an IP, is unresolvable, or whose line is not a link pass through
    untouched.
    """
    lines = _normalize_lines(lines)
    resolver = resolver or (lambda h: resolve_host(h, family))

    parsed, hosts = [], set()
    for ln in lines:
        pr = parse_line(ln)
        parsed.append(pr)
        if pr and not _is_ip(pr[0]):
            hosts.add(pr[0])

    mapping = _resolve_all(hosts, resolver, workers, verbose)

    out, rewritten = [], 0
    for ln, pr in zip(lines, parsed):
        new = ln
        if pr:
            ip = mapping.get(pr[0])
            if ip:
                cand = pr[1](ip)
                if cand:
                    new, rewritten = cand, rewritten + 1
        out.append(new)

    stats = {
        "lines": len(lines),
        "links": sum(p is not None for p in parsed),
        "already_ip": sum(p is not None and _is_ip(p[0]) for p in parsed),
        "domains": len(hosts),
        "resolved": len(mapping),
        "failed": len(hosts) - len(mapping),
        "rewritten": rewritten,
    }
    return out, stats


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _read(source: str) -> list:
    if source == "-":
        return sys.stdin.read().splitlines()
    try:
        with open(source, "r", encoding="utf-8") as fh:
            return fh.read().splitlines()
    except OSError as exc:
        raise SystemExit(f"error: cannot read {source}: {exc}") from exc


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Replace server domains in proxy links with resolved IPs "
                    "(1:1 line count; unparseable/IP/failed lines pass through).")
    ap.add_argument("input", help="file with one link per line, or '-' for stdin")
    ap.add_argument("-o", "--output", help="write result here (default: stdout)")
    ap.add_argument("--family", choices=("4", "6", "any"), default="4",
                    help="record type to resolve (default: 4; 'any' prefers IPv4)")
    ap.add_argument("--workers", type=int, default=50, help="concurrent DNS lookups")
    ap.add_argument("-v", "--verbose", action="store_true", help="warn about failed resolutions")
    ap.add_argument("--self-test", action="store_true", help="run built-in checks")
    args = ap.parse_args(argv)

    if args.self_test:
        return _self_test()

    out, st = resolve_lines(_read(args.input), family=args.family,
                            workers=args.workers, verbose=args.verbose)
    print(f"[*] {st['lines']} lines | {st['links']} links | {st['already_ip']} already IPs | "
          f"{st['domains']} unique domains | {st['resolved']} resolved | "
          f"{st['failed']} failed | {st['rewritten']} lines rewritten", file=sys.stderr)

    text = "\n".join(out) + ("\n" if out else "")
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)
    return 0


def _self_test() -> int:
    fake = {"example.com": "93.184.216.34",
            "v6.test": "2606:2800:220:1:248:1893:25c8:1946"}
    vmess = base64.b64encode(json.dumps(
        {"v": "2", "ps": "n1", "add": "example.com", "port": "443",
         "id": "b831381d-6324-4d53-ad4f-8cda48b30811", "net": "ws", "tls": "tls"}
    ).encode()).decode()
    links = [
        f"vmess://{vmess}#kept",
        "vless://uuid@example.com:443?security=tls&type=ws#A",
        "trojan://hunter2@EXAMPLE.com:8443?sni=example.com#T",
        "ss://" + base64.b64encode(b"aes-256-gcm:pw@example.com:8388").decode(),
        "ss://" + base64.b64encode(b"aes-256-gcm:pw").decode() + "@example.com:8388?plugin=x#S",
        "vless://uuid@1.2.3.4:443#already-ip",
        "vless://uuid@dead.invalid:443#unresolvable",
        "vless://uuid@[v6.test]:443#v6",
        "not a link",
        "",
    ]
    out, st = resolve_lines(links, resolver=fake.get)
    assert len(out) == len(links), "line count must be preserved"
    assert json.loads(_b64decode(out[0][len("vmess://"):].split("#")[0]))["add"] == "93.184.216.34"
    assert out[0].endswith("#kept")
    assert "93.184.216.34:443?security=tls&type=ws#A" in out[1]
    assert "hunter2@93.184.216.34:8443?sni=example.com#T" in out[2]
    assert "aes-256-gcm:pw@93.184.216.34:8388" in _b64decode(out[3][5:]).decode()
    assert out[4] == "ss://" + base64.b64encode(b"aes-256-gcm:pw").decode() + "@93.184.216.34:8388?plugin=x#S"
    assert out[5] == links[5] and out[6] == links[6], "IP / unresolvable must be untouched"
    assert "uuid@[2606:2800:220:1:248:1893:25c8:1946]:443#v6" in out[7]
    assert out[8] == links[8] and out[9] == ""
    assert st["rewritten"] == 6 and st["already_ip"] == 1 and st["failed"] == 1
    print("self-test OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
