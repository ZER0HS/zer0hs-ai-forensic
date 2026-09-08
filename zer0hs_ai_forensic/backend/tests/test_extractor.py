from extractor import _clean_url, extract_domain_from_url, extract_indicators


def test_extract_domain_from_url_handles_scheme_path_and_port():
    assert extract_domain_from_url("http://paypa1-verify.com/login?x=1") == "paypa1-verify.com"
    assert extract_domain_from_url("https://example.com:8443/a/b") == "example.com"
    assert extract_domain_from_url("example.com/no-scheme") == "example.com"


def test_extracts_public_ip():
    result = extract_indicators("connect to 45.155.205.77 now")
    assert "45.155.205.77" in result["ips"]


def test_filters_private_ips_out_of_public_list():
    result = extract_indicators("internal host 192.168.1.5 and 10.0.0.9 and public 8.8.8.8")
    assert "8.8.8.8" in result["ips"]
    assert "192.168.1.5" not in result["ips"]
    assert "10.0.0.9" not in result["ips"]
    assert "192.168.1.5" in result["private_ips"]
    assert "10.0.0.9" in result["private_ips"]


def test_extracts_domain_from_url():
    result = extract_indicators("Click http://paypa1-verification.com/login now")
    assert "paypa1-verification.com" in result["domains"]
    assert "http://paypa1-verification.com/login" in result["urls"]


def test_extracts_email_and_its_domain():
    result = extract_indicators("contact attacker@evil-mail.ru for details")
    assert "attacker@evil-mail.ru" in result["emails"]
    assert "evil-mail.ru" in result["domains"]


def test_domains_capped_at_ten():
    text = " ".join(f"site{i}.com" for i in range(25))
    result = extract_indicators(text)
    assert len(result["domains"]) <= 10


def test_no_indicators_in_plain_text():
    result = extract_indicators("just a normal sentence with no indicators")
    assert result["ips"] == []
    assert result["domains"] == []
    assert result["urls"] == []
    assert result["emails"] == []


# ── Trailing punctuation / prose brackets around a URL ──────────────────

def test_url_wrapped_in_parentheses_loses_the_closing_paren():
    """The reported bug: an email or report wraps a URL in prose
    parentheses, and the raw regex match pulls the closing ")" in as part
    of the URL, breaking threat-intel lookups and sandbox scans on
    exactly the indicator most worth checking."""
    result = extract_indicators("See (http://www.instagram.com/capitalone/) for the fake profile.")
    assert "http://www.instagram.com/capitalone/" in result["urls"]
    assert "http://www.instagram.com/capitalone/)" not in result["urls"]


def test_url_ending_a_sentence_loses_the_period():
    result = extract_indicators("Click http://evil.com/login now.")
    assert "http://evil.com/login" in result["urls"]


def test_url_with_trailing_bracket_and_quote_stacked():
    assert _clean_url("http://evil.com/a]'") == "http://evil.com/a"


def test_url_with_balanced_closing_paren_keeps_it():
    """A URL that legitimately ends in a balanced ")" — the classic
    Wikipedia-style link with a parenthetical in the path — must not lose
    it just because it's also a closing bracket."""
    url = "https://en.wikipedia.org/wiki/Phishing_(disambiguation)"
    assert _clean_url(url) == url


def test_url_with_unbalanced_trailing_bracket_variants():
    assert _clean_url("http://evil.com/a)") == "http://evil.com/a"
    assert _clean_url("http://evil.com/a]") == "http://evil.com/a"
    assert _clean_url("http://evil.com/a}") == "http://evil.com/a"


def test_homoglyph_punycode_domain_is_extracted_and_flagged_as_typosquat():
    """xn--pypal-4ve.com is the real punycode encoding of "p<Cyrillic
    а>ypal.com" — a homoglyph domain using U+0430 in place of Latin "a",
    exactly what a browser or mail client would show a human reader after
    decoding it. check_typosquatting() punycode-decodes and folds known
    look-alike characters before comparing against brand names, so this
    is caught rather than silently passing as an unrelated string."""
    from rule_engine import check_typosquatting

    text = "Verify now: http://xn--pypal-4ve.com/login"
    indicators = extract_indicators(text)
    assert "xn--pypal-4ve.com" in indicators["domains"]

    result = check_typosquatting("xn--pypal-4ve.com")
    assert result["detected"]
    assert result["technique"] == "homoglyph"
    assert result["brand"] == "paypal"
