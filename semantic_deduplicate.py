#!/usr/bin/env python3
"""Semantic deduplication of proxy configuration links.

Standalone Python port of the SemanticDeduplicate functionality from
xray-knife (github.com/lilendian0x00/xray-knife).

Two links are *semantic duplicates* when they describe the same proxy for
connection purposes: same protocol, host, port, credential, transport
(`type=`/`net`) and TLS mode (`security=`). Links that differ only in their
remark (`#fragment`), query-parameter order, base64 padding/variant, or
letter case collapse into one. The first occurrence wins by default.

Supported: vless, vmess, trojan, ss (SIP002 + legacy), ssr, and any other
`scheme://userinfo@host:port?query#fragment` URI generically. Lines that
cannot be parsed are kept verbatim (unique by definition); blank lines and
`#` comments are skipped.

Usage:
    python semantic_deduplicate.py links.txt
    python semantic_deduplicate.py links.txt -o unique.txt --show-duplicates
    cat links.txt | python semantic_deduplicate.py -
    python semantic_deduplicate.py --self-test
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from urllib.parse import parse_qsl, unquote, urlsplit

__all__ = ["Identity", "LinkError", "parse_link", "semantic_deduplicate", "main"]


class LinkError(ValueError):
    """Raised when a link cannot be parsed into an identity."""


@dataclass(frozen=True)
class Identity:
    """The semantic identity of a proxy link.

    Two links are duplicates when their Identity keys are equal. Cosmetic
    fields (remark, parameter order, encoding) never reach the key.
    """

    scheme: str
    host: str
    port: int
    credential: str
    network: str = ""
    security: str = ""

    def key(self) -> tuple:
        return (self.scheme, self.host, self.port, self.credential,
                self.network, self.security)


# --------------------------------------------------------------------------
# Parsing helpers
# --------------------------------------------------------------------------

def _b64decode(data: str) -> bytes:
    """Decode standard or URL-safe base64, tolerating missing padding."""
    data = data.strip().replace("-", "+").replace("_", "/")
    data += "=" * (-len(data) % 4)
    if not data.isascii():
        # base64 alphabet is ASCII-only; b64decode would leak a
        # UnicodeEncodeError here (e.g. a blob truncated to "...").
        raise LinkError("payload contains non-ASCII characters (not base64)")
    try:
        return base64.b64decode(data, validate=False)
    except ValueError as exc:  # covers binascii.Error AND UnicodeError
        raise LinkError(f"bad base64 payload: {exc}") from exc


def _normalize_host(host: str) -> str:
    return (host or "").strip().strip("[]").rstrip(".").lower()


def _to_port(value) -> int:
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        raise LinkError(f"invalid port: {value!r}") from None
    if not 0 <= port <= 65535:
        raise LinkError(f"port out of range: {port}")
    return port


def _split_host_port(hostport: str) -> tuple:
    """Split 'host:port' or '[v6]:port' into (host, port)."""
    hostport = hostport.strip()
    if hostport.startswith("["):
        host, _, rest = hostport[1:].partition("]")
        return _normalize_host(host), _to_port(rest.lstrip(":") or 0)
    if ":" in hostport:
        host, _, port = hostport.rpartition(":")
        return _normalize_host(host), _to_port(port)
    return _normalize_host(hostport), 0


# --------------------------------------------------------------------------
# Per-scheme parsers
# --------------------------------------------------------------------------

def _parse_vmess(link: str) -> Identity:
    payload = link[len("vmess://"):].split("#", 1)[0].split("?", 1)[0]
    try:
        obj = json.loads(_b64decode(payload).decode("utf-8", "replace"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise LinkError(f"vmess payload is not valid JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise LinkError("vmess payload is not a JSON object")
    return Identity(
        scheme="vmess",
        host=_normalize_host(str(obj.get("add", ""))),
        port=_to_port(obj.get("port") or 0),
        credential=str(obj.get("id", "")).strip(),
        network=str(obj.get("net", "")).strip().lower(),
        security=str(obj.get("tls", "")).strip().lower(),
    )


def _parse_ss(link: str) -> Identity:
    body = link[len("ss://"):].split("#", 1)[0]
    if "@" in body:  # SIP002
        userinfo, hostport = body.rsplit("@", 1)
        try:
            cred = _b64decode(userinfo).decode("utf-8", "replace")
        except LinkError:
            cred = unquote(userinfo)  # plaintext method:password
        host, port = _split_host_port(hostport)
    else:  # legacy base64 whole-link
        decoded = _b64decode(body).decode("utf-8", "replace")
        if "@" not in decoded:
            raise LinkError("legacy ss link does not contain '@'")
        cred, hostport = decoded.rsplit("@", 1)
        host, port = _split_host_port(hostport)
    method, _, password = cred.partition(":")
    return Identity("ss", host, port, f"{method.strip().lower()}:{password}")


def _parse_ssr(link: str) -> Identity:
    body = link[len("ssr://"):].split("#", 1)[0].split("?", 1)[0]
    main = _b64decode(body).decode("utf-8", "replace").split("/?", 1)[0]
    try:
        host, port, protocol, method, obfs, password_b64 = main.rsplit(":", 5)
    except ValueError:
        raise LinkError("ssr link has unexpected format") from None
    password = _b64decode(password_b64).decode("utf-8", "replace")
    credential = f"{method.lower()}:{protocol.lower()}:{obfs.lower()}:{password}"
    return Identity("ssr", _normalize_host(host), _to_port(port), credential)


def _parse_generic_uri(link: str) -> Identity:
    try:
        parts = urlsplit(link)
        port = parts.port  # raises on invalid port
    except ValueError as exc:
        raise LinkError(f"malformed URI: {exc}") from exc
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    credential = unquote(parts.username or "") or unquote(query.get("auth", ""))
    if parts.password:
        credential = f"{credential}:{unquote(parts.password)}"
    return Identity(
        scheme=parts.scheme.lower(),
        host=_normalize_host(parts.hostname or ""),
        port=port or 0,
        credential=credential,
        network=(query.get("type") or query.get("net") or "").strip().lower(),
        security=(query.get("security") or "").strip().lower(),
    )


def parse_link(link: str) -> Identity:
    """Parse a proxy link into its semantic Identity."""
    if "://" not in link:
        raise LinkError(f"not a URI link: {link[:60]!r}")
    scheme = link.split("://", 1)[0].strip().lower()
    if scheme == "vmess":
        return _parse_vmess(link)
    if scheme == "ss":
        return _parse_ss(link)
    if scheme == "ssr":
        return _parse_ssr(link)
    return _parse_generic_uri(link)


# --------------------------------------------------------------------------
# Deduplication
# --------------------------------------------------------------------------

def semantic_deduplicate(links: Iterable[str], *, keep: str = "first",
                         drop_invalid: bool = False):
    """Deduplicate proxy links by semantic identity.

    Returns (unique, duplicates). Unparseable lines are kept verbatim
    (deduping only against identical raw copies) — unless drop_invalid=True.
    """
    entries = []
    for raw in links:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            identity = parse_link(line)
        except Exception:  # malformed link: never fatal
            identity = None
            if drop_invalid:
                continue
        entries.append((line, identity))

    seen: set = set()
    unique, duplicates = [], []
    scan = entries if keep == "first" else entries[::-1]
    for line, identity in scan:
        key = identity.key() if identity is not None else ("raw", line)
        if key in seen:
            duplicates.append(line)
        else:
            seen.add(key)
            unique.append(line)
    if keep == "last":
        unique.reverse()
        duplicates.reverse()
    return unique, duplicates


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _read_lines(source: str) -> list:
    if source == "-":
        return sys.stdin.read().splitlines()
    try:
        with open(source, "r", encoding="utf-8") as fh:
            return fh.read().splitlines()
    except OSError as exc:
        raise SystemExit(f"error: cannot read {source}: {exc}") from exc


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Remove semantically duplicate proxy config links "
                    "(standalone port of xray-knife's SemanticDeduplicate).")
    parser.add_argument("input", help="file with one link per line, or '-' for stdin")
    parser.add_argument("-o", "--output", help="write unique links here (default: stdout)")
    parser.add_argument("--drop-invalid", action="store_true",
                        help="discard lines that cannot be parsed instead of keeping them")
    parser.add_argument("--keep", choices=("first", "last"), default="first",
                        help="which occurrence of a duplicate group to keep")
    parser.add_argument("-d", "--show-duplicates", action="store_true",
                        help="print removed duplicates to stderr")
    parser.add_argument("--self-test", action="store_true", help="run built-in checks")
    args = parser.parse_args(argv)

    if args.self_test:
        return _self_test()

    unique, duplicates = semantic_deduplicate(_read_lines(args.input),
                                              keep=args.keep,
                                              drop_invalid=args.drop_invalid)
    if args.show_duplicates:
        for line in duplicates:
            print(f"duplicate removed: {line}", file=sys.stderr)
    print(f"{len(unique) + len(duplicates)} links -> {len(unique)} unique, "
          f"{len(duplicates)} duplicate(s) removed", file=sys.stderr)

    text = "\n".join(unique) + ("\n" if unique else "")
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)
    return 0


def _self_test() -> int:
    vmess_json = json.dumps({"v": "2", "ps": "Node B", "add": "Example.com",
                             "port": "443", "id": "b831381d-6324-4d53-ad4f-8cda48b30811",
                             "net": "ws", "tls": "tls"})
    links = [
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=tls&type=ws#Node A",
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@EXAMPLE.com:443?type=ws&security=tls#Renamed dup",
        "vmess://" + base64.b64encode(vmess_json.encode()).decode(),  # different protocol -> kept
        "trojan://hunter2@example.com:443?security=tls#Trojan",
        "ss://" + base64.b64encode(b"aes-256-gcm:pw@1.2.3.4:8388").decode(),
        "ss://" + base64.urlsafe_b64encode(b"aes-256-gcm:pw").decode().rstrip("=")
        + "@1.2.3.4:8388#Tag",  # same node, SIP002 -> dup
        "hysteria2://letmein@example.com:8443?sni=example.com#Hy2",
        "", "# comment",
        "not a link at all",  # kept verbatim
    ]
    unique, duplicates = semantic_deduplicate(links)
    assert len(unique) == 6 and len(duplicates) == 2, (unique, duplicates)
    unique_last, _ = semantic_deduplicate(links, keep="last")
    assert any("#Tag" in u for u in unique_last)
    assert parse_link("vmess://" + base64.b64encode(vmess_json.encode()).decode()) == \
           Identity("vmess", "example.com", 443, "b831381d-6324-4d53-ad4f-8cda48b30811", "ws", "tls")
    print("self-test OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
