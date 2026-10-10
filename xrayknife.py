import json
import os

import resolver

# ---------- CONFIG ----------
INPUT_JSON = "out/results.json"
OUTPUT_DIR = "sub"
OUTPUT_200 = "g200.txt"
OUTPUT_200_L = "g200_lite.txt"
OUTPUT_NOT_200 = "gn200.txt"
OUTPUT_NOT_200_L = "gn200_lite.txt"
MAX_DELAY = 3000  # max delay (ms) allowed in output files
LITE_TOP_N = 100


# ----------------------------

def load_entries(path):
    if not os.path.exists(path):
        raise FileNotFoundError(f"JSON file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        # tolerate {"results": [...]} style wrappers
        for v in data.values():
            if isinstance(v, list):
                return v
        return [data]
    return []


def get_link(entry):
    link = entry.get("link")
    if link:
        return link
    proto = entry.get("protocol") or {}
    return proto.get("remark") or proto.get("address") or ""


def get_code(entry):
    code = entry.get("code")
    if code is None:
        return None
    try:
        return int(code)
    except (ValueError, TypeError):
        return None


def get_delay(entry):
    delay = entry.get("delay")
    if delay is None:
        return None
    try:
        return float(delay)
    except (ValueError, TypeError):
        return None


def ensure_dir(path):
    if not os.path.isdir(path):
        os.makedirs(path, exist_ok=True)


def write_links(links, path, top_n=None):
    with open(path, "w", encoding="utf-8") as f:
        for link in links[:top_n]:
            f.write(link + "\n")
    print(f"Wrote {len(links)} links to {path}")


def main():
    ensure_dir(OUTPUT_DIR)

    entries = load_entries(INPUT_JSON)
    print(f"Loaded {len(entries)} entries from {INPUT_JSON}")

    ok_links = []  # code == 200
    bad_links = []  # code != 200, must have delay

    for entry in entries:
        code = get_code(entry)
        delay = get_delay(entry)
        link = get_link(entry)

        if not link:
            continue

        if code == 200:
            d = delay if delay is not None else float("inf")
            if d <= MAX_DELAY:
                ok_links.append((d, link))
        else:
            if delay is not None and delay <= MAX_DELAY:
                bad_links.append((delay, link))

    ok_links.sort(key=lambda x: x[0])
    bad_links.sort(key=lambda x: x[0])

    ok_links = [link for _, link in ok_links]
    bad_links = [link for _, link in bad_links]

    fmt = lambda s: " | ".join(f"{k}={v}" for k, v in s.items())

    ok_links, status = resolver.resolve_lines(ok_links, family='any')
    print("OK:", fmt(status))

    bad_links, status = resolver.resolve_lines(bad_links, family='any')
    print("BAD:", fmt(status))

    write_links(ok_links,
                os.path.join(OUTPUT_DIR, OUTPUT_200))

    write_links(ok_links,
                os.path.join(OUTPUT_DIR, OUTPUT_200_L), top_n=LITE_TOP_N)

    write_links(bad_links,
                os.path.join(OUTPUT_DIR, OUTPUT_NOT_200))

    write_links(bad_links,
                os.path.join(OUTPUT_DIR, OUTPUT_NOT_200_L), top_n=LITE_TOP_N)


if __name__ == "__main__":
    main()
