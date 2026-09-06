import httpx
import os
import asyncio

URLSCAN_KEY = os.getenv("URLSCAN_API_KEY", "")

async def sandbox_url(url: str) -> dict:
    if not URLSCAN_KEY:
        return {"error": "URLScan API key not configured", "url": url, "status": "error"}

    # Clean URL
    url = url.strip()
    if not url.startswith("http"):
        url = "https://" + url

    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:

            # Submit scan — header must be exactly "API-Key"
            submit = await client.post(
                "https://urlscan.io/api/v1/scan/",
                headers={
                    "API-Key": URLSCAN_KEY,
                    "Content-Type": "application/json"
                },
                json={
                    "url": url,
                    "visibility": "unlisted"
                }
            )

            print(f"[URLScan] Status: {submit.status_code}")
            print(f"[URLScan] Response: {submit.text[:300]}")

            # Handle errors
            if submit.status_code == 400:
                try:
                    err = submit.json()
                    msg = err.get("message", "Bad request")
                    desc = err.get("description", "")
                except Exception:
                    msg = submit.text
                    desc = ""
                return {
                    "url": url,
                    "status": "error",
                    "error": f"{msg}. {desc}".strip()
                }

            if submit.status_code == 429:
                return {
                    "url": url,
                    "status": "error",
                    "error": "Rate limit reached — wait a minute and try again"
                }

            if submit.status_code == 401:
                return {
                    "url": url,
                    "status": "error",
                    "error": "Invalid API key — check your URLSCAN_API_KEY in .env"
                }

            if submit.status_code not in (200, 201):
                return {
                    "url": url,
                    "status": "error",
                    "error": f"Unexpected status: {submit.status_code} — {submit.text[:200]}"
                }

            data     = submit.json()
            uuid     = data.get("uuid")
            if not uuid:
                return {"url": url, "status": "error", "error": "No UUID in response"}

            result_url  = f"https://urlscan.io/result/{uuid}/"
            screenshot  = f"https://urlscan.io/screenshots/{uuid}.png"

            # Wait for scan — docs say wait 10-30s then poll
            await asyncio.sleep(15)

            # Poll for result
            for attempt in range(6):
                res = await client.get(
                    f"https://urlscan.io/api/v1/result/{uuid}/",
                    headers={"API-Key": URLSCAN_KEY}
                )
                print(f"[URLScan] Poll {attempt+1}: {res.status_code}")

                if res.status_code == 200:
                    r        = res.json()
                    verdicts = r.get("verdicts", {}).get("overall", {})
                    page     = r.get("page", {})
                    return {
                        "url":        url,
                        "scan_uuid":  uuid,
                        "result_url": result_url,
                        "screenshot": screenshot,
                        "malicious":  verdicts.get("malicious", False),
                        "score":      verdicts.get("score", 0),
                        "tags":       verdicts.get("tags", []),
                        "final_url":  page.get("url", url),
                        "ip":         page.get("ip", ""),
                        "country":    page.get("country", ""),
                        "server":     page.get("server", ""),
                        "status":     "complete"
                    }

                if res.status_code == 404:
                    # Still scanning — wait and retry
                    await asyncio.sleep(5)
                    continue

                if res.status_code == 410:
                    return {
                        "url": url,
                        "status": "error",
                        "error": "Scan result was deleted by URLScan"
                    }

            # Timed out but scan was submitted
            return {
                "url":        url,
                "scan_uuid":  uuid,
                "result_url": result_url,
                "screenshot": screenshot,
                "status":     "pending",
                "message":    "Scan submitted but still processing — click 'View full report' in ~30 seconds"
            }

    except Exception as e:
        return {"url": url, "status": "error", "error": str(e)}


async def check_hash_vt(hash_value: str, vt_key: str) -> dict:
    if not vt_key:
        return {"error": "VirusTotal key not set"}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                f"https://www.virustotal.com/api/v3/files/{hash_value}",
                headers={"x-apikey": vt_key}
            )
            if r.status_code == 404:
                return {"hash": hash_value, "found": False,
                    "message": "Hash not in VirusTotal database"}
            d     = r.json().get("data", {}).get("attributes", {})
            stats = d.get("last_analysis_stats", {})
            return {
                "hash":       hash_value,
                "found":      True,
                "malicious":  stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "total":      sum(stats.values()),
                "name":       d.get("meaningful_name", ""),
                "type":       d.get("type_description", ""),
                "size":       d.get("size", 0),
            }
    except Exception as e:
        return {"hash": hash_value, "error": str(e)}