"""
Shared test setup. Env vars MUST be set before any backend module is
imported (several read os.getenv at module import time), which is why this
runs at collection time in conftest.py rather than inside a fixture.

Every third-party API key is force-blanked here so that a test which
forgets to mock an external call fails loudly (a real request with no key
configured returns an explicit "not configured" result) instead of
silently hitting a live, paid, rate-limited service.
"""
import os

os.environ["LLM_PROVIDER"]       = "ollama"
os.environ["OLLAMA_URL"]         = "http://localhost:11434"
os.environ["API_KEY"]            = ""
os.environ["CORS_ORIGINS"]       = "http://localhost:5173"
os.environ["URLSCAN_API_KEY"]    = ""
os.environ["VIRUSTOTAL_API_KEY"] = ""
os.environ["ABUSEIPDB_API_KEY"]  = ""
os.environ.pop("ANTHROPIC_API_KEY", None)

from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES_DIR


@pytest.fixture(autouse=True)
def _isolate_feedback_dir(tmp_path, monkeypatch):
    """Every test's case-file writes go to a throwaway directory, never
    the real backend/feedback/ the running app actually uses. Without
    this, any test that exercises /analyze (which unconditionally calls
    save_analysis()) pollutes real case history — which is exactly what
    happened while writing test_analyze_integration.py before this
    fixture existed. autouse=True means no test has to opt in or
    remember to do this itself."""
    import feedback
    monkeypatch.setattr(feedback, "FEEDBACK_DIR", tmp_path)


def load_fixture(name: str) -> bytes:
    return (FIXTURES_DIR / name).read_bytes()


@pytest.fixture
def client():
    """A fresh FastAPI TestClient. Imported lazily so conftest's env vars
    are guaranteed to be set before main.py (and everything it imports) is
    loaded for the first time."""
    from fastapi.testclient import TestClient
    import main
    return TestClient(main.app)
