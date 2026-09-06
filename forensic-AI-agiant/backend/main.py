from fastapi import FastAPI, UploadFile, File, Form, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
from typing import Optional
from datetime import datetime
import os

load_dotenv()

# ── Create app FIRST ──────────────────────────────────────────────────────
app = FastAPI(title="Forensic AI Agent", version="2.0.0")

# ── CORS ──────────────────────────────────────────────────────────────────
app.add_middleware(CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)

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
from agent         import run_analysis
from parser        import extract_text
from threat_intel  import check_indicator, check_all_indicators
from fp_tp_scorer  import score_case, score_single
from extractor     import extract_indicators
from sandbox       import sandbox_url
from rule_engine   import run_rules
from knowledge_base import get_relevant_patterns
from feedback      import save_analysis, save_feedback, get_accuracy_stats

# ── Health check ──────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {
        "status":    "ok",
        "timestamp": datetime.utcnow().isoformat(),
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
            async with httpx.AsyncClient(timeout=3) as client:
                r = await client.get("http://localhost:11434/api/tags")
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
        "timestamp":   datetime.utcnow().isoformat(),
        "abuseipdb":   bool(os.getenv("ABUSEIPDB_API_KEY")),
        "virustotal":  bool(os.getenv("VIRUSTOTAL_API_KEY")),
        "urlscan":     bool(os.getenv("URLSCAN_API_KEY")),
    }

# ── Main analysis endpoint ────────────────────────────────────────────────
@app.post("/analyze")
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

        # Step 2 — threat intel on all indicators
        threat_results = await check_all_indicators(indicators)

        # Step 3 — deterministic rule engine
        rule_findings = run_rules(raw_text, indicators, threat_results)

        # Step 4 — RAG pattern matching
        patterns = get_relevant_patterns(raw_text, indicators)

        # Step 5 — LLM forensic analysis
        forensic = await run_analysis(raw_text, rule_findings, patterns)

        # Step 6 — unified FP/TP verdict
        verdict = await score_case(
            raw_text,
            indicators,
            threat_results,
            forensic,
            rule_findings,
            patterns
        )

        # Step 7 — apply hard rule overrides
        override = rule_findings.get("verdict_override")
        if override:
            reason = rule_findings.get("override_reason", "")
            if override == "FP" and verdict["verdict"] == "TP":
                verdict["verdict"]    = "FP"
                verdict["confidence"] = 90
                verdict["risk_level"] = "clean"
                verdict["reasoning"]  = (
                    f"[RULE OVERRIDE → FP] {reason} | "
                    f"LLM had said: {verdict.get('reasoning','')}"
                )
                verdict["iocs"] = []
            elif override == "TP" and verdict["verdict"] == "FP":
                verdict["verdict"]    = "TP"
                verdict["confidence"] = 90
                verdict["reasoning"]  = (
                    f"[RULE OVERRIDE → TP] {reason} | "
                    f"LLM had said: {verdict.get('reasoning','')}"
                )

        # Build result
        result = {
            **forensic,
            "indicators":    indicators,
            "threat_results": threat_results,
            "case_verdict":  verdict,
            "eml_headers":   eml_data,
            "rule_findings": rule_findings,
            "patterns":      patterns,
            "hash_results":  []
        }

        # Step 8 — save for feedback loop
        case_id         = save_analysis(result)
        result["case_id"] = case_id

        return result

    except Exception as e:
        import traceback
        traceback.print_exc()
        return JSONResponse(
            {"error": f"Analysis failed: {str(e)}"},
            status_code=500
        )

# ── Single indicator threat check ─────────────────────────────────────────
@app.post("/threat-check")
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
        return JSONResponse(
            {"error": f"Threat check failed: {str(e)}"},
            status_code=500
        )

# ── URL sandbox ───────────────────────────────────────────────────────────
@app.post("/sandbox")
async def sandbox(
    request: Request,
    url:     str = Form(...)
):
    try:
        result = await sandbox_url(url)
        return result
    except Exception as e:
        return JSONResponse(
            {"error": f"Sandbox failed: {str(e)}"},
            status_code=500
        )

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
    return get_accuracy_stats()