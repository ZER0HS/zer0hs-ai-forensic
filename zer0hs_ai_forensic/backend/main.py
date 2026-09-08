import asyncio
import logging
import os
from datetime import datetime, timezone
from typing import Optional

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("zer0hs_ai_forensic")

# ── Create app FIRST ──────────────────────────────────────────────────────
app = FastAPI(title="ZER0HS", version="2.0.0")

# ── Rate limiting ────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── CORS — origins come from the environment, never "*" ────────────────────
_cors_origins = [
    o.strip() for o in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",")
    if o.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-API-Key"],
)

# ── API key auth ─────────────────────────────────────────────────────────
# A single shared secret is enough for a personal/small-team local tool.
# Left unset (the .env.example default) this is a no-op, so local dev keeps
# working with zero setup — set API_KEY before exposing this past localhost.
_API_KEY = os.getenv("API_KEY", "")


def require_api_key(x_api_key: str = Header(default="")):
    if _API_KEY and x_api_key != _API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return True


# ── File size limit middleware ─────────────────────────────────────────────
@app.middleware("http")
async def limit_upload_size(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > 10 * 1024 * 1024:
        return JSONResponse(
            {"error": "File too large. Max 10MB."},
            status_code=413
        )
    return await call_next(request)

# ── Security headers middleware ────────────────────────────────────────────
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"]        = "DENY"
    response.headers["X-XSS-Protection"]       = "1; mode=block"
    return response

# ── Import modules AFTER app is created ───────────────────────────────────
import confirmed_indicators
from combined_analysis import run_combined_analysis
from parser        import extract_text, ZipGuardError
from threat_intel  import check_indicator, check_all_indicators
from fp_tp_scorer  import score_single
from extractor     import extract_domain_from_url, extract_indicators
from sandbox       import sandbox_url, check_all_hashes
from rule_engine   import check_typosquatting, run_rules, shortcircuit_forensic, shortcircuit_verdict
from knowledge_base import get_relevant_patterns
from feedback      import (
    get_accuracy_stats, get_case, get_verdict_distribution,
    list_cases, save_analysis, save_feedback,
)

# ── Health check ──────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {
        "status":    "ok",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "provider":  os.getenv("LLM_PROVIDER", "claude"),
        "version":   "2.0.0"
    }

# ── Status endpoint ───────────────────────────────────────────────────────
@app.get("/status")
async def status():
    provider = os.getenv("LLM_PROVIDER", "claude")
    model    = (os.getenv("OLLAMA_MODEL", "qwen2.5:14b")
                if provider == "ollama"
                else "claude-sonnet-4-5")

    provider_ok = False
    error_msg   = ""

    if provider == "ollama":
        try:
            import httpx
            ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434")
            async with httpx.AsyncClient(timeout=3) as client:
                r = await client.get(f"{ollama_url}/api/tags")
                if r.status_code == 200:
                    models = [m["name"] for m in r.json().get("models", [])]
                    if any(model in m for m in models):
                        provider_ok = True
                    else:
                        error_msg = f"Model '{model}' not found. Run: ollama pull {model}"
                else:
                    error_msg = "Ollama not responding"
        except Exception:
            error_msg = "Ollama not running — open the Ollama app"
    else:
        provider_ok = bool(os.getenv("ANTHROPIC_API_KEY"))
        if not provider_ok:
            error_msg = "ANTHROPIC_API_KEY missing in .env"

    return {
        "provider":    provider,
        "model":       model,
        "provider_ok": provider_ok,
        "error":       error_msg,
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "abuseipdb":   bool(os.getenv("ABUSEIPDB_API_KEY")),
        "virustotal":  bool(os.getenv("VIRUSTOTAL_API_KEY")),
        "urlscan":     bool(os.getenv("URLSCAN_API_KEY")),
    }

def _confirmed_hits_to_threat_results(hits: list) -> list:
    """Turns confirmed_indicators.get_hits() output into the same shape
    threat_intel.check_ip()/check_domain() return, so run_rules() and
    everything downstream treats a human-confirmed verdict exactly like a
    fresh AbuseIPDB/VirusTotal result — no special-casing needed anywhere
    else in the pipeline."""
    results = []
    for h in hits:
        is_tp = h["verdict"] == "TP"
        entry = {
            "type":        h["type"],
            "value":       h["indicator"],
            "abuse_score": 100 if is_tp else 0,
            "source":      f"confirmed by human feedback ({h['case_id']})",
        }
        if h["type"] == "domain":
            entry["malicious_votes"]  = 1 if is_tp else 0
            entry["suspicious_votes"] = 0
            entry["total_scanners"]   = 1
        else:
            entry["country"]       = "Unknown"
            entry["isp"]           = "Unknown"
            entry["total_reports"] = 1 if is_tp else 0
            entry["usage_type"]    = "Unknown"
        results.append(entry)
    return results


# ── Main analysis endpoint ────────────────────────────────────────────────
@app.post("/analyze", dependencies=[Depends(require_api_key)])
@limiter.limit("10/minute")
async def analyze(
    request: Request,
    file:    Optional[UploadFile] = File(None),
    text:    Optional[str]        = Form(None)
):
    try:
        raw_text = text or ""
        eml_data = None

        # Parse file if uploaded
        if file:
            raw_text, eml_data = await extract_text(file)

        # Step 1 — extract indicators
        indicators = extract_indicators(raw_text)

        # Add routing IPs from email headers
        if eml_data and eml_data.get("routing_ips"):
            for ip in eml_data["routing_ips"]:
                if (ip not in indicators["ips"] and
                    ip not in indicators.get("private_ips", [])):
                    indicators["ips"].append(ip)

        # Step 1.5 — check the confirmed-indicator memory before spending
        # any threat-intel quota or LLM tokens on indicators a human has
        # already judged. A hit here needs no fresh API call at all.
        confirmed_hits = confirmed_indicators.get_hits(indicators)
        confirmed_values = {h["indicator"] for h in confirmed_hits}
        if confirmed_hits:
            logger.info("Confirmed-indicator memory hit, skipping fresh lookup for: %s",
                        [h["indicator"] for h in confirmed_hits])
        remaining_indicators = {
            "ips":     [i for i in indicators.get("ips", []) if i not in confirmed_values],
            "domains": [d for d in indicators.get("domains", []) if d not in confirmed_values],
        }

        # Step 2 — threat intel (only for indicators without a confirmed
        # verdict) + attachment hash checks, in parallel
        attachments = eml_data.get("attachments", []) if eml_data else []
        live_threat_results, hash_results = await asyncio.gather(
            check_all_indicators(remaining_indicators),
            check_all_hashes(attachments),
        )
        threat_results = live_threat_results + _confirmed_hits_to_threat_results(confirmed_hits)

        # Step 3 — deterministic rule engine (ground truth — LLM can't override it)
        rule_findings = run_rules(raw_text, indicators, threat_results, hash_results, attachments)

        # Step 4 — RAG pattern matching
        patterns = get_relevant_patterns(raw_text, indicators)

        override = rule_findings.get("verdict_override")

        if override:
            # Step 5/6 — the rule engine already reached a maximally-confident
            # verdict deterministically; skip both LLM calls entirely rather
            # than run them and overrule them after the fact.
            logger.info("Rule engine short-circuit: %s (%s)", override, rule_findings.get("override_reason"))
            forensic = shortcircuit_forensic(raw_text, rule_findings)
            verdict  = shortcircuit_verdict(rule_findings, threat_results, hash_results)
        else:
            # Steps 5+6 — one LLM call for both the forensic write-up and
            # the verdict, instead of two sequential ones. See
            # combined_analysis.py for why this replaced the old
            # run_analysis() + score_case() pair on this path.
            combined  = await run_combined_analysis(
                raw_text, indicators, threat_results, rule_findings, patterns, eml_data
            )
            forensic = combined["forensic"]
            verdict  = combined["verdict"]

        # Build result
        result = {
            **forensic,
            "indicators":     indicators,
            "threat_results": threat_results,
            "case_verdict":   verdict,
            "eml_headers":    eml_data,
            "rule_findings":  rule_findings,
            "patterns":       patterns,
            "hash_results":   hash_results
        }

        # Step 7 — save for feedback loop
        case_id         = save_analysis(result)
        result["case_id"] = case_id

        return result

    except ZipGuardError as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    except Exception as e:
        logger.exception("Analysis failed")
        return JSONResponse(
            {"error": f"Analysis failed: {str(e)}"},
            status_code=500
        )

# ── Single indicator threat check ─────────────────────────────────────────
@app.post("/threat-check", dependencies=[Depends(require_api_key)])
@limiter.limit("20/minute")
async def threat_check(
    request:   Request,
    indicator: str = Form(...),
    context:   str = Form("")
):
    try:
        threat_data = await check_indicator(indicator)
        scoring     = await score_single(indicator, threat_data, context)
        return {
            "indicator":    indicator,
            "threat_intel": threat_data,
            "ai_verdict":   scoring
        }
    except Exception as e:
        logger.exception("Threat check failed")
        return JSONResponse(
            {"error": f"Threat check failed: {str(e)}"},
            status_code=500
        )

# ── URL sandbox ───────────────────────────────────────────────────────────
# Two separate actions rather than one: Check is fast (threat intel + the
# rule engine's typosquat check, no screenshot) and gives a real FP/TP
# verdict in seconds; Scan is the slow URLScan.io submission, opt-in and
# clearly labeled as such. Scan always includes the same verdict Check
# would produce, run concurrently with the URLScan wait so combining them
# costs nothing extra — a screenshot with no reasoning attached is a
# shallow answer for something that took 15-45 seconds to get.
async def _check_url_verdict(url: str, context: str = "") -> dict:
    domain = extract_domain_from_url(url) or url.strip()
    threat_data      = await check_indicator(domain)
    typosquat_result = check_typosquatting(domain)
    scoring          = await score_single(domain, threat_data, context, typosquat_result)
    return {
        "indicator":    domain,
        "threat_intel": threat_data,
        "typosquat":    typosquat_result,
        "ai_verdict":   scoring,
    }


@app.post("/sandbox/check", dependencies=[Depends(require_api_key)])
@limiter.limit("20/minute")
async def sandbox_check(
    request: Request,
    url:     str = Form(...),
    context: str = Form(""),
):
    try:
        return await _check_url_verdict(url, context)
    except Exception as e:
        logger.exception("Sandbox check failed")
        return JSONResponse({"error": f"Check failed: {str(e)}"}, status_code=500)


@app.post("/sandbox/scan", dependencies=[Depends(require_api_key)])
@limiter.limit("5/minute")
async def sandbox_scan(
    request: Request,
    url:     str = Form(...),
):
    try:
        scan_result, verdict_result = await asyncio.gather(
            sandbox_url(url),
            _check_url_verdict(url),
        )
        return {**scan_result, "check": verdict_result}
    except Exception as e:
        logger.exception("Sandbox scan failed")
        return JSONResponse({"error": f"Scan failed: {str(e)}"}, status_code=500)

# ── Human feedback ────────────────────────────────────────────────────────
@app.post("/feedback")
async def submit_feedback(
    case_id:       str  = Form(...),
    human_verdict: str  = Form(...),
    is_correct:    bool = Form(...),
    notes:         str  = Form("")
):
    success = save_feedback(case_id, human_verdict, is_correct, notes)
    return {"success": success, "case_id": case_id}

# ── Accuracy stats ────────────────────────────────────────────────────────
@app.get("/accuracy")
async def accuracy():
    stats = get_accuracy_stats()
    stats["verdict_distribution"] = get_verdict_distribution()
    return stats

# ── Case history ──────────────────────────────────────────────────────────
@app.get("/cases")
async def cases(limit: int = 50):
    return {"cases": list_cases(limit)}

@app.get("/cases/{case_id}")
async def case_detail(case_id: str):
    data = get_case(case_id)
    if data is None:
        return JSONResponse({"error": "Case not found"}, status_code=404)
    return data
