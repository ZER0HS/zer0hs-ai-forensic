"""Shared retry policies for every external call in the pipeline.

Before this, a single dropped connection to Ollama, Claude, AbuseIPDB,
VirusTotal, or URLScan failed the entire analysis with a raw 500 — wasting
every pipeline step that had already succeeded. These policies are split by
how "expensive to retry" the call is:

- `network_retry` — fast third-party APIs (AbuseIPDB, VirusTotal, URLScan).
  Their timeouts are short (~10-30s), so retrying the whole call a couple of
  times on any transient network error is cheap.
- `llm_retry` — Ollama/Claude generation calls. These can legitimately take
  30-180s. Only retry on a *connection* failure (the service isn't up yet, a
  brief network blip) — never on a read timeout, since a read timeout almost
  always means "still generating," not "transient failure," and retrying
  that would multiply an already-long wait for no benefit.
"""
import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

network_retry = retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=0.5, min=0.5, max=4),
    retry=retry_if_exception_type((httpx.TransportError, httpx.TimeoutException)),
    reraise=True,
)

llm_retry = retry(
    stop=stop_after_attempt(2),
    wait=wait_exponential(multiplier=1, min=1, max=3),
    retry=retry_if_exception_type((httpx.ConnectError, httpx.ConnectTimeout)),
    reraise=True,
)
