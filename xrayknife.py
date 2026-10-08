import json
import os

# ---------- CONFIG ----------
INPUT_JSON = "out/results.json"
OUTPUT_DIR = "sub"
OUTPUT_200 = "g200.txt"
OUTPUT_NOT_200 = "gn200.txt"
MAX_DELAY = 3000  # max delay (ms) allowed in output files


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
    if top_n is not None:
        links = links[:top_n]
    with open(path, "w", encoding="utf-8") as f:
        for link in links:
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

    write_links([link for _, link in ok_links],
                os.path.join(OUTPUT_DIR, OUTPUT_200))
    write_links([link for _, link in ok_links],
                os.path.join(OUTPUT_DIR, OUTPUT_200), top_n=50)

    write_links([link for _, link in bad_links],
                os.path.join(OUTPUT_DIR, OUTPUT_NOT_200))
    write_links([link for _, link in bad_links],
                os.path.join(OUTPUT_DIR, OUTPUT_NOT_200), top_n=50)


if __name__ == "__main__":
    main()
