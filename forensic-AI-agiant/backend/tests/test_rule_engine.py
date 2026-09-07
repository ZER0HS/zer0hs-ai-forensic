from rule_engine import (
    analyze_text_patterns,
    check_dangerous_attachments,
    check_typosquatting,
    is_private_ip,
    run_rules,
    shortcircuit_forensic,
    shortcircuit_verdict,
)


# ── Typosquatting ────────────────────────────────────────────────────────

def test_legitimate_brand_domains_are_never_self_flagged():
    """Regression test for a real bug found while writing these tests:
    the Levenshtein check compared a domain to a brand name without
    excluding an exact match, so every 5+ letter brand's own domain
    (distance 0 from itself) was flagged as "impersonating" itself."""
    for domain in ["google.com", "paypal.com", "chase.com", "netflix.com",
                   "mail.google.com", "accounts.google.com"]:
        result = check_typosquatting(domain)
        assert not result["detected"], f"false positive on {domain}: {result}"


def test_real_typosquats_are_still_caught():
    for domain in ["paypa1.com", "g00gle.com", "paypal-verify-account.net", "chas3.com"]:
        result = check_typosquatting(domain)
        assert result["detected"], f"missed typosquat: {domain}"


# ── Text pattern analysis ───────────────────────────────────────────────

def test_urgency_and_phishing_keywords_score_high():
    text = "Your account will be suspended. Verify immediately or act now."
    analysis = analyze_text_patterns(text)
    assert analysis["phishing_keywords"]
    assert analysis["urgency_patterns"]
    assert analysis["total_score"] > 0


def test_ordinary_text_scores_zero():
    analysis = analyze_text_patterns("Let's grab lunch tomorrow at noon.")
    assert analysis["total_score"] == 0


def test_zero_width_characters_evade_keyword_matching():
    """Known limitation: plain substring matching is defeated by
    zero-width-space injection inside a keyword. Documented as a known gap
    rather than silently assumed handled."""
    zwsp = chr(0x200B)  # zero-width space — built from a codepoint, not a
                         # literal invisible character, so it can't get
                         # silently dropped or altered by file encoding.
    text = zwsp.join(["verify", "your", "account", "immediately"])
    analysis = analyze_text_patterns(text)
    assert analysis["phishing_keywords"] == []


# ── Dangerous attachments ───────────────────────────────────────────────

def test_detects_dangerous_extensions():
    found = check_dangerous_attachments("please run invoice.exe or setup.ps1")
    assert any(f.endswith(".exe") for f in found)
    assert any(f.endswith(".ps1") for f in found)


def test_ignores_safe_extensions():
    found = check_dangerous_attachments("see attached report.pdf and photo.jpg")
    assert found == []


# ── Private IP detection ────────────────────────────────────────────────

def test_private_ip_ranges():
    for ip in ["10.0.0.1", "172.16.5.4", "192.168.1.1", "127.0.0.1"]:
        assert is_private_ip(ip)
    assert not is_private_ip("8.8.8.8")


# ── Full rule engine — deterministic overrides ──────────────────────────

def test_typosquat_plus_high_risk_ip_is_definite_tp():
    findings = run_rules(
        text="click here",
        indicators={"ips": ["1.2.3.4"], "domains": ["paypa1.com"]},
        threat_results=[{"type": "ip", "value": "1.2.3.4", "abuse_score": 80}],
    )
    assert findings["verdict_override"] == "TP"


def test_all_clean_is_definite_fp():
    findings = run_rules(
        text="hey, lunch tomorrow?",
        indicators={"ips": ["8.8.8.8"], "domains": ["google.com"]},
        threat_results=[{"type": "ip", "value": "8.8.8.8", "abuse_score": 0}],
    )
    assert findings["verdict_override"] == "FP"


def test_malicious_attachment_hash_alone_is_definite_tp():
    findings = run_rules(
        text="see attached invoice",
        indicators={"ips": [], "domains": []},
        threat_results=[],
        hash_results=[{"filename": "invoice.pdf.exe", "malicious": 12, "total": 70}],
    )
    assert findings["verdict_override"] == "TP"
    assert any("malicious" in i.lower() for i in findings["hard_tp_indicators"])


def test_ambiguous_case_has_no_override():
    """A single weak signal shouldn't be enough for either definite
    override — this is the "genuinely ambiguous middle" the LLM path
    exists for."""
    findings = run_rules(
        text="please review this document",
        indicators={"ips": ["9.9.9.9"], "domains": []},
        threat_results=[{"type": "ip", "value": "9.9.9.9", "abuse_score": 30}],
    )
    assert findings["verdict_override"] is None


def test_hash_results_defaults_to_empty_for_backward_compatibility():
    findings = run_rules("hi", {"ips": [], "domains": []}, [])
    assert findings["verdict_override"] == "FP"


# ── Arabic-language phishing: documents a real gap and its mitigation ───

ARABIC_URGENCY_TEXT = (
    "يجب عليك التحقق من هويتك خلال 24 ساعة وإلا سيتم إيقاف حسابك بشكل دائم. "
    "اضغط هنا فوراً"
)


def test_arabic_phishing_text_not_caught_by_english_only_keywords():
    """PHISHING_KEYWORDS / URGENCY_PATTERNS are English-only, so genuine
    Arabic-language urgency/social-engineering phrasing scores zero on the
    text analyzer. This is a real, known gap — documented explicitly here
    rather than silently assumed to work. See IMPLEMENTATION_PLAN.md for
    the recommended fix (a parallel non-English pattern list)."""
    analysis = analyze_text_patterns(ARABIC_URGENCY_TEXT)
    assert analysis["total_score"] == 0


def test_arabic_phishing_still_caught_via_language_agnostic_signals():
    """Even though the text scorer misses the Arabic wording, a
    typosquatting domain or a known-malicious IP is language-agnostic —
    defense in depth still catches the email via a different signal."""
    findings = run_rules(
        text=ARABIC_URGENCY_TEXT + " http://paypa1-arabic-verify.com/verify",
        indicators={"ips": ["185.220.101.45"], "domains": ["paypa1-arabic-verify.com"]},
        threat_results=[{"type": "ip", "value": "185.220.101.45", "abuse_score": 90}],
    )
    assert findings["verdict_override"] == "TP"
    assert findings["text_analysis"]["total_score"] == 0  # confirms the gap is real
    assert findings["typosquat_results"]                  # confirms the mitigation fires


# ── Short-circuit builders (no LLM call needed) ─────────────────────────

def test_shortcircuit_verdict_matches_override():
    findings = run_rules("hi", {"ips": [], "domains": []}, [])  # -> FP override
    verdict = shortcircuit_verdict(findings)
    assert verdict["verdict"] == "FP"
    assert verdict["confidence"] == 95
    assert verdict["iocs"] == []


def test_shortcircuit_forensic_uses_literal_evidence_slice():
    findings = run_rules("hi", {"ips": [], "domains": []}, [])
    forensic = shortcircuit_forensic("hello world, this is the evidence", findings)
    assert forensic["highlight"]["text"] == "hello world, this is the evidence"
    assert "<" not in forensic["highlight"]["text"]


def test_shortcircuit_forensic_surfaces_hard_indicators_as_anomalies():
    """Found via a live end-to-end run: a definite-TP short-circuit left
    `anomalies` empty, so the UI showed "0 anomalies" on a confirmed
    phishing verdict — reading as "nothing found" right next to a case
    summary listing exactly what was found. The rule engine's hard
    indicators should show up as anomalies too, not just in the summary."""
    findings = run_rules(
        text="click here",
        indicators={"ips": ["1.2.3.4"], "domains": ["paypa1.com"]},
        threat_results=[{"type": "ip", "value": "1.2.3.4", "abuse_score": 80}],
    )
    forensic = shortcircuit_forensic("click here", findings)
    assert len(forensic["anomalies"]) > 0
    assert all(a["severity"] == "critical" for a in forensic["anomalies"])
