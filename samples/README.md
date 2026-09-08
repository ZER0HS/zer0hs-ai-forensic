# Sample emails

Three synthetic `.eml` files to try the tool with right away, so you don't
have to write your own test case first. They're the same files used as
test fixtures in `zer0hs_ai_forensic/backend/tests/fixtures/` — safe,
made up, no real people or real malicious infrastructure.

Upload any of these on the Analyze tab, or run them through
`backend/scripts/run_benchmark.py` along with the rest of the benchmark set.

| File | What it is | Expected verdict |
|---|---|---|
| `typosquat_phishing.eml` | A PayPal-impersonation email from `paypa1-verification.com`, sent from a flagged IP, with urgency language | TP, high confidence |
| `legit_business.eml` | An ordinary invoice reminder from a colleague, clean sender, no technical indicators | FP, high confidence |
| `arabic_phishing.eml` | The same typosquat-plus-malicious-IP pattern as the first file, written in Arabic, to demonstrate the Arabic-language keyword/pattern set | TP, high confidence |

None of these contain real credentials, real malicious URLs, or a real
attachment payload of any kind. The IP address used in the phishing
samples is a real, publicly documented Tor exit node (used here only so
the AbuseIPDB check has something genuine to find) rather than an
invented address.
