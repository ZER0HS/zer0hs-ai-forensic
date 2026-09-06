from extractor import extract_indicators


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


def test_homoglyph_punycode_domain_is_extracted_but_not_flagged_as_typosquat():
    """Known limitation: a punycode-encoded homoglyph domain (e.g. a
    Cyrillic look-alike registered as xn--...) is extracted as a domain
    fine, but check_typosquatting()'s plain substring/Levenshtein match
    against ASCII brand names never fires for it, since the punycode
    string doesn't resemble the brand name as text. Documented here as a
    regression target for a future IDN-aware typosquat check rather than
    silently assumed to be handled."""
    from rule_engine import check_typosquatting

    text = "Verify now: http://xn--pypal-4ve.com/login"
    indicators = extract_indicators(text)
    assert "xn--pypal-4ve.com" in indicators["domains"]

    result = check_typosquatting("xn--pypal-4ve.com")
    assert not result["detected"]
