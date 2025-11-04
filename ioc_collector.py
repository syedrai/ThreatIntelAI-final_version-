#!/usr/bin/env python3
"""
IOC Collector: normalize and classify IOCs from a text or JSON file.
Saves normalized_iocs.csv by default.
"""
import re
import csv
import json
from pathlib import Path
from typing import List, Dict

IOC_TYPE_PATTERNS = {
    "ip": re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$"),
    "ipv6": re.compile(r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$"),
    "domain": re.compile(r"^(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$"),
    "url": re.compile(r"^https?://", re.IGNORECASE),
    "hash": re.compile(r"^[A-Fa-f0-9]{32,128}$"),
}

def normalize_ioc(raw: str) -> Dict:
    s = raw.strip()
    if not s:
        return None
    s = s.split('#', 1)[0].strip().strip('"\'>)<(')
    for t, pat in IOC_TYPE_PATTERNS.items():
        if pat.search(s):
            return {"ioc": s, "type": t}
    if '/' in s or ':' in s:
        return {"ioc": s, "type": "url"}
    return {"ioc": s, "type": "unknown"}

def collect_from_file(path: str) -> List[Dict]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(path)
    results = []
    if p.suffix.lower() == '.json':
        with p.open() as f:
            obj = json.load(f)
        items = obj if isinstance(obj, list) else obj.get('iocs', [])
        for it in items:
            if isinstance(it, str):
                n = normalize_ioc(it)
            elif isinstance(it, dict) and 'ioc' in it:
                n = normalize_ioc(it['ioc'])
                n.update({k: v for k, v in it.items() if k != 'ioc'})
            else:
                continue
            if n:
                results.append(n)
    else:
        with p.open() as f:
            for line in f:
                n = normalize_ioc(line)
                if n:
                    results.append(n)
    # dedupe preserving first occurrence
    seen = set()
    deduped = []
    for r in results:
        key = (r['ioc'], r.get('type'))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(r)
    return deduped

def save_csv(iocs: List[Dict], outpath: str = 'data/normalized_iocs.csv'):
    Path(outpath).parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ['ioc', 'type'] + sorted({k for d in iocs for k in d.keys() if k not in ('ioc', 'type')})
    with open(outpath, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in iocs:
            writer.writerow(r)

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('file', help='Input file (.txt or .json)')
    parser.add_argument('--out', default='data/normalized_iocs.csv')
    args = parser.parse_args()
    recs = collect_from_file(args.file)
    save_csv(recs, args.out)
    print(f"Saved {len(recs)} normalized IOCs -> {args.out}")
