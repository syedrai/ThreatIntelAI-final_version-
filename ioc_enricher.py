#!/usr/bin/env python3
"""
ThreatIntelAI — IOC Enricher
-----------------------------------------------------
Enrich Indicators of Compromise (IOCs) using real-world
threat intelligence APIs:
- VirusTotal v3
- AbuseIPDB
- GreyNoise (Community / API key)
- IPinfo

Supports:
✅ Asynchronous concurrent lookups
✅ Auto-retries with exponential backoff
✅ Caching system for speed
✅ CSV export of enriched results
"""

import os
import csv
import asyncio
import async_timeout
import aiohttp
import json
from pathlib import Path
from typing import List, Dict
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from dotenv import load_dotenv
from utils import logger, open_cache

# ---------------------------------------------------------------------
# Load API keys from environment (.env file)
# ---------------------------------------------------------------------
load_dotenv()

VT_API_KEY = os.getenv('VT_API_KEY')
ABUSEIPDB_KEY = os.getenv('ABUSEIPDB_KEY')
GREYNOISE_KEY = os.getenv('GREYNOISE_KEY', None)  # Optional
IPINFO_TOKEN = os.getenv('IPINFO_TOKEN')

MAX_CONCURRENCY = int(os.getenv('THREATINTELAI_MAX_CONCURRENCY', '8'))
TIMEOUT = int(os.getenv('THREATINTELAI_TIMEOUT', '12'))
RETRIES = int(os.getenv('THREATINTELAI_RETRIES', '3'))

# API endpoints
VT_BASE = "https://www.virustotal.com/api/v3"
ABUSEIPDB_CHECK = "https://api.abuseipdb.com/api/v2/check"
GREYNOISE_COMM = "https://api.greynoise.io/v3/community"
GREYNOISE_IP = "https://api.greynoise.io/v3/ip"
IPINFO_BASE = "https://ipinfo.io"

sem = asyncio.Semaphore(MAX_CONCURRENCY)

# Retry decorator for resilience
retry_deco = retry(
    reraise=True,
    stop=stop_after_attempt(RETRIES),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    retry=retry_if_exception_type((aiohttp.ClientError, asyncio.TimeoutError))
)

# ---------------------------------------------------------------------
# Enricher class — performs lookups across threat intelligence APIs
# ---------------------------------------------------------------------
class Enricher:
    def __init__(self, session: aiohttp.ClientSession):
        self.session = session

    # ----------------------------- VirusTotal ------------------------
    @retry_deco
    async def vt_lookup(self, ioc: str, ioc_type: str) -> Dict:
        if not VT_API_KEY:
            logger.debug("VT_API_KEY not set; skipping VirusTotal lookup.")
            return {}
        headers = {"x-apikey": VT_API_KEY}
        if ioc_type == 'ip':
            url = f"{VT_BASE}/ip_addresses/{ioc}"
        elif ioc_type == 'domain':
            url = f"{VT_BASE}/domains/{ioc}"
        elif ioc_type == 'hash':
            url = f"{VT_BASE}/files/{ioc}"
        else:
            return {}

        async with sem:
            async with async_timeout.timeout(TIMEOUT):
                async with self.session.get(url, headers=headers) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    elif resp.status == 404:
                        return {"not_found": True}
                    else:
                        logger.warning("VT status %s: %s", resp.status, await resp.text())
                        return {}

    # ----------------------------- AbuseIPDB -------------------------
    @retry_deco
    async def abuseipdb_lookup(self, ip: str) -> Dict:
        if not ABUSEIPDB_KEY:
            logger.debug("ABUSEIPDB_KEY not set; skipping AbuseIPDB lookup.")
            return {}
        headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}

        async with sem:
            async with async_timeout.timeout(TIMEOUT):
                async with self.session.get(ABUSEIPDB_CHECK, headers=headers, params=params) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    else:
                        logger.warning("AbuseIPDB status %s: %s", resp.status, await resp.text())
                        return {}

    # ----------------------------- GreyNoise -------------------------
    @retry_deco
    async def greynoise_lookup(self, ip: str) -> Dict:
        """
        Uses GreyNoise Community API by default.
        If a GREYNOISE_KEY is set in .env, uses paid API instead.
        """
        if GREYNOISE_KEY:
            url = f"{GREYNOISE_IP}/{ip}"
            headers = {"key": GREYNOISE_KEY}
        else:
            url = f"{GREYNOISE_COMM}/{ip}"
            headers = {}

        async with sem:
            async with async_timeout.timeout(TIMEOUT):
                async with self.session.get(url, headers=headers) as resp:
                    if resp.status == 200:
                        try:
                            return await resp.json()
                        except Exception:
                            return {}
                    elif resp.status == 404:
                        return {"not_found": True}
                    else:
                        logger.warning("GreyNoise status %s: %s", resp.status, await resp.text())
                        return {}

    # ----------------------------- IPinfo ----------------------------
    @retry_deco
    async def ipinfo_lookup(self, ip: str) -> Dict:
        params = {'token': IPINFO_TOKEN} if IPINFO_TOKEN else {}
        url = f"{IPINFO_BASE}/{ip}/json"
        async with sem:
            async with async_timeout.timeout(TIMEOUT):
                async with self.session.get(url, params=params) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    else:
                        logger.warning("IPinfo status %s: %s", resp.status, await resp.text())
                        return {}

    # ----------------------------- Enrichment Core -------------------
    async def enrich_record(self, rec: Dict) -> Dict:
        ioc = rec.get('ioc')
        itype = rec.get('type', 'unknown')
        out = dict(rec)
        cache_key = f"enrich::{itype}::{ioc}"

        # Cache check
        with open_cache() as cache:
            cached = cache.get(cache_key)
            if cached:
                logger.debug("Cache hit for %s", cache_key)
                out.update(cached)
                return out

        try:
            vt_data, abuse_data, gn_data, ipinfo_data = {}, {}, {}, {}
            if itype == 'ip':
                vt_data, abuse_data, gn_data, ipinfo_data = await asyncio.gather(
                    self.vt_lookup(ioc, 'ip'),
                    self.abuseipdb_lookup(ioc),
                    self.greynoise_lookup(ioc),
                    self.ipinfo_lookup(ioc)
                )
            elif itype == 'domain':
                vt_data = await self.vt_lookup(ioc, 'domain')
            elif itype == 'hash':
                vt_data = await self.vt_lookup(ioc, 'hash')
            elif itype == 'url':
                domain = ioc.split('://', 1)[-1].split('/', 1)[0]
                vt_data = await self.vt_lookup(domain, 'domain')

            rep = vt_data.get('data', {}).get('attributes', {}).get('reputation') if isinstance(vt_data, dict) else None
            if rep is None and isinstance(abuse_data, dict):
                rep = abuse_data.get('data', {}).get('abuseConfidenceScore')

            geo = ipinfo_data.get('country') if isinstance(ipinfo_data, dict) else None
            asn = ipinfo_data.get('org') if isinstance(ipinfo_data, dict) else None

            aggregated = {
                "reputation_score": rep,
                "malicious_votes": abuse_data.get('data', {}).get('totalReports') if isinstance(abuse_data, dict) else None,
                "geo_country": geo,
                "asn": asn,
                "vt_raw": vt_data or None,
                "abuseipdb_raw": abuse_data or None,
                "greynoise_raw": gn_data or None,
                "ipinfo_raw": ipinfo_data or None,
            }
            out.update(aggregated)
            with open_cache(writeback=True) as cache:
                cache[cache_key] = aggregated
        except Exception as e:
            logger.exception("Error enriching %s: %s", ioc, e)
            out['enrich_error'] = str(e)
        return out


# ----------------------------- Helpers -----------------------------
async def enrich_batch_async(records: List[Dict]) -> List[Dict]:
    conn = aiohttp.TCPConnector(limit_per_host=MAX_CONCURRENCY)
    timeout = aiohttp.ClientTimeout(total=TIMEOUT)
    async with aiohttp.ClientSession(connector=conn, timeout=timeout) as session:
        enricher = Enricher(session)
        tasks = [asyncio.create_task(enricher.enrich_record(rec)) for rec in records]
        return [await t for t in asyncio.as_completed(tasks)]

def enrich_batch(records: List[Dict]) -> List[Dict]:
    if not records:
        return []
    loop = asyncio.get_event_loop()
    return loop.run_until_complete(enrich_batch_async(records))

def save_csv(records: List[Dict], outpath: str = 'data/enriched_iocs.csv'):
    Path(outpath).parent.mkdir(parents=True, exist_ok=True)
    fieldnames = sorted({k for d in records for k in d.keys()})
    with open(outpath, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in records:
            writer.writerow({k: json.dumps(v) if isinstance(v, (dict, list)) else v for k, v in r.items()})

# ----------------------------- CLI Entry ---------------------------
if __name__ == '__main__':
    import argparse
    from ioc_collector import collect_from_file

    parser = argparse.ArgumentParser(description="Enrich IOCs with real-world threat intelligence data.")
    parser.add_argument('file', help="Path to file containing IOCs (CSV or text)")
    parser.add_argument('--out', default='data/enriched_iocs.csv', help="Output CSV path")
    args = parser.parse_args()

    p = Path(args.file)
    if p.suffix.lower() == '.csv':
        import csv as _csv
        with p.open() as fh:
            recs = [row for row in _csv.DictReader(fh)]
    else:
        recs = collect_from_file(args.file)

    enriched = enrich_batch(recs)
    save_csv(enriched, args.out)
    print(f"\n✅ Saved {len(enriched)} enriched IOCs -> {args.out}")
