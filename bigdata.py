import base64
import os
import sys
import pathlib as pl
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

import config
import formatters

import semantic_deduplicate


def parse_link_spec(entry):
    if isinstance(entry, str):
        return entry, config.DEFAULT_TARGET_TYPE
    if isinstance(entry, dict):
        return entry["url"], entry.get("type", config.DEFAULT_TARGET_TYPE)
    raise ValueError(f"Invalid SUB_LINKS entry: {entry!r}")


def download(url):
    r = requests.get(url, headers={"User-Agent": config.USER_AGENT},
                     timeout=config.REQUEST_TIMEOUT)
    r.raise_for_status()
    return r.text


def try_decode_base64(text):
    """
    If the text looks like base64-encoded data, decode and return it.
    Otherwise return the original text unchanged.
    """
    stripped = "".join(text.split())  # remove all whitespace/newlines
    if not stripped or len(stripped) % 4 != 0:
        return text
    # Heuristic: valid base64 charset (and not just a plain proxy/config line)
    import re
    if not re.fullmatch(r"[A-Za-z0-9+/=_-]+", stripped):
        return text
    try:
        decoded = base64.b64decode(stripped + "=" * (-len(stripped) % 4),
                                   validate=True)
        decoded_text = decoded.decode("utf-8")
    except Exception:
        return text
    # Sanity check: decoded content should look like config lines
    if decoded_text and any(
            proto in decoded_text.lower()
            for proto in ("vmess", "vless", "trojan", "ss://", "ssr://", "hysteria", "tuic", "://")
    ):
        print(f"[*] Detected base64 content — decoded ({len(decoded_text)} bytes)")
        return decoded_text
    return text


def fetch_all(specs):
    results = []
    with ThreadPoolExecutor(max_workers=min(8, len(specs) or 1)) as ex:
        futures = {ex.submit(download, url): (url, t) for url, t in specs}
        for fut in as_completed(futures):
            url, target = futures[fut]
            try:
                text = try_decode_base64(fut.result())
                results.append((url, target, text))
                print(f"[+] Downloaded: {url} ({len(text)} bytes)")
            except Exception as e:
                print(f"[!] Failed {url}: {e}", file=sys.stderr)
    return results


def extract_lines(text):
    return [ln.strip() for ln in text.splitlines() if ln.strip()]


def format_line(line, target):
    if not target:
        return line
    fn = formatters.FORMATTERS.get(target)
    if not fn:
        print(f"[!] No formatter registered for '{target}' — keeping line as-is",
              file=sys.stderr)
        return line
    return fn(line)


def chunked(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def clean_out_dir(out_dir):
    """Remove all files inside out_dir (but keep the dir itself)."""
    if not os.path.isdir(out_dir):
        return
    for name in os.listdir(out_dir):
        path = os.path.join(out_dir, name)
        if os.path.isfile(path) or os.path.islink(path):
            os.remove(path)
        else:
            import shutil
            shutil.rmtree(path)
    print(f"[*] Cleaned output directory: {out_dir}")


def write_split(items, out_dir, max_lines, prefix="configs"):
    clean_out_dir(out_dir)
    os.makedirs(out_dir, exist_ok=True)
    if not items:
        print(f"[!] No items to write to {out_dir}.")
        return
    written_files = []
    for idx, chunk in enumerate(chunked(items, max_lines), start=1):
        filename = f"{prefix}_{idx:03d}.txt"
        path = os.path.join(out_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(chunk) + "\n")
        written_files.append(filename)
        print(f"[+] Wrote {len(chunk)} -> {path}")

    # Save the index of chunked files
    index_path = os.path.join(out_dir, "files.txt")
    with open(index_path, "w", encoding="utf-8") as f:
        f.write("\n".join(written_files) + "\n")
    print(f"[+] Wrote file index -> {index_path} ({len(written_files)} files)")


def main():
    if not config.SUB_LINKS:
        print("[!] No SUB_LINKS configured.")
        return

    specs = [parse_link_spec(e) for e in config.SUB_LINKS]
    print(f"[*] Fetching {len(specs)} subscription(s)...")

    merged = []
    for url, target, text in fetch_all(specs):
        lines = extract_lines(text)
        formatted = [format_line(ln, target) for ln in lines]
        print(f"[*] {url}: {len(formatted)} lines (target={target or 'original'})")
        merged.extend(formatted)

    history = pl.Path('in/sub/all.txt').read_text().splitlines()
    print(f"[*] History: {len(history)}")
    merged.extend(history)

    print(f"[*] Total: {len(merged)}")

    merged, dup = semantic_deduplicate.semantic_deduplicate(merged, keep='first', drop_invalid=True)
    print(f"[*] Deduplicated: {len(merged) + len(dup)} -> {len(merged)}")

    write_split(merged, config.OUTPUT_DIR, config.MAX_LINES_PER_FILE)

    (pl.Path(config.OUTPUT_DIR) / "all.txt").write_text("\n".join(merged))

    print("[*] Done.")


if __name__ == "__main__":
    main()
