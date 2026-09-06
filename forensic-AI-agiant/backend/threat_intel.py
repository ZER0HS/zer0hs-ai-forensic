import httpx
import os
import re
import asyncio
from cachetools import TTLCache

from retry_utils import network_retry

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY")
VT_KEY        = os.getenv("VIRUSTOTAL_API_KEY")

# Same IP/domain shows up across many emails — no reason to re-query
# AbuseIPDB/VirusTotal every time. Short TTL since a freshly-reported IP
# should still show up reasonably quickly.
_cache = TTLCache(maxsize=2048, ttl=600)  # 10 minutes


def is_ip(value: str) -> bool:
    return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value))


@network_retry
async def _fetch_ip(ip: str) -> dict:
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90}
        )
        d = r.json().get("data", {})
        return {
            "type": "ip",
            "value": ip,
            "abuse_score": d.get("abuseConfidenceScore", 0),
            "country": d.get("countryCode", "Unknown"),
            "isp": d.get("isp", "Unknown"),
            "total_reports": d.get("totalReports", 0),
            "last_reported": d.get("lastReportedAt", None),
            "usage_type": d.get("usageType", "Unknown"),
            "source": "AbuseIPDB"
        }


async def check_ip(ip: str) -> dict:
    cache_key = f"ip:{ip}"
    if cache_key in _cache:
        return _cache[cache_key]
    try:
        result = await _fetch_ip(ip)
    except Exception as e:
        return {"type": "ip", "value": ip, "abuse_score": 0, "error": str(e), "source": "AbuseIPDB"}
    _cache[cache_key] = result
    return result


@network_retry
async def _fetch_domain(domain: str) -> dict:
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": VT_KEY}
        )
        d     = r.json().get("data", {}).get("attributes", {})
        stats = d.get("last_analysis_stats", {})
        mal   = stats.get("malicious", 0)
        sus   = stats.get("suspicious", 0)
        total = sum(stats.values()) or 1
        score = int(((mal + sus) / total) * 100)
        return {
            "type": "domain",
            "value": domain,
            "abuse_score": score,
            "malicious_votes": mal,
            "suspicious_votes": sus,
            "total_scanners": total,
            "source": "VirusTotal"
        }


async def check_domain(domain: str) -> dict:
    if not VT_KEY:
        return {"type": "domain", "value": domain, "abuse_score": 0, "source": "VirusTotal (not configured)"}
    cache_key = f"domain:{domain}"
    if cache_key in _cache:
        return _cache[cache_key]
    try:
        result = await _fetch_domain(domain)
    except Exception as e:
        return {"type": "domain", "value": domain, "abuse_score": 0, "error": str(e), "source": "VirusTotal"}
    _cache[cache_key] = result
    return result


async def check_indicator(value: str) -> dict:
    value = value.strip()
    if is_ip(value):
        return await check_ip(value)
    else:
        return await check_domain(value)


async def check_all_indicators(indicators: dict) -> list:
    tasks = []
    for ip in indicators.get("ips", []):
        tasks.append(check_ip(ip))
    for domain in indicators.get("domains", []):
        tasks.append(check_domain(domain))
    results = await asyncio.gather(*tasks)
    return list(results)
