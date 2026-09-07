"""
Strict response schemas for every LLM call in the pipeline.

Why this exists: the previous implementation parsed LLM output with a
best-effort regex/replace fallback (`clean_json` in llm_client.py) that
silently returned `{}` on anything it couldn't parse. A malformed or
hijacked model response would then quietly become a confident-looking
default verdict ("FP", 50% confidence) with no indication anything went
wrong. These Pydantic models make that failure loud instead of silent:
`llm_client.ask_llm_json()` validates every response against one of these,
re-prompts once on failure, and only falls back to the model's own
(clearly conservative) defaults after a second failure.

Field validators here normalize cosmetic issues (wrong case, out-of-range
numbers) rather than rejecting them — that keeps the precious one-shot
re-prompt reserved for genuinely broken/malicious responses instead of a
model that just returned "tp" instead of "TP".
"""
from typing import List, Literal, Optional
from pydantic import BaseModel, Field, field_validator

RiskLevel = Literal["critical", "high", "medium", "low", "clean"]
Verdict = Literal["TP", "FP"]
# CaseVerdict specifically can also land in a third state — see its own
# verdict field below for why score_single (a single indicator, not a
# full case) doesn't get this third option.
CaseVerdictValue = Literal["TP", "FP", "NEEDS_REVIEW"]


def _clamp_int(v, lo: int, hi: int, default: int) -> int:
    try:
        return max(lo, min(hi, int(v)))
    except (TypeError, ValueError):
        return default


def _as_str_list(v) -> list:
    """Be forgiving about a model returning a single string instead of a
    list of strings for a findings/actions/factors field."""
    if v is None:
        return []
    if isinstance(v, str):
        return [v] if v.strip() else []
    if isinstance(v, list):
        return [str(x) for x in v if str(x).strip()]
    return []


# ── Forensic analysis (agent.py) ────────────────────────────────────────────

class Entities(BaseModel):
    persons: List[str] = Field(default_factory=list)
    places: List[str] = Field(default_factory=list)
    times: List[str] = Field(default_factory=list)
    orgs: List[str] = Field(default_factory=list)

    @field_validator("persons", "places", "times", "orgs", mode="before")
    @classmethod
    def _coerce(cls, v):
        return _as_str_list(v)


class Anomaly(BaseModel):
    severity: RiskLevel = "low"
    title: str = ""
    description: str = ""

    @field_validator("severity", mode="before")
    @classmethod
    def _normalize_severity(cls, v):
        v = str(v).strip().lower()
        return v if v in ("critical", "high", "medium", "low", "clean") else "low"


class TimelineEvent(BaseModel):
    time: str = ""
    event: str = ""
    actors: str = ""
    anomaly: bool = False

    @field_validator("time", "event", "actors", mode="before")
    @classmethod
    def _coerce_str(cls, v):
        # Seen for real (not a synthetic test) while running the accuracy
        # benchmark against Ollama: the model returned "actors" as
        # ["IT Helpdesk <...>"] instead of a plain string when an email
        # involved a distinct sender vs. reply-to. Cosmetic — join it
        # rather than burning a re-prompt over it.
        if isinstance(v, list):
            return ", ".join(str(x) for x in v)
        return v

    @field_validator("anomaly", mode="before")
    @classmethod
    def _coerce_bool(cls, v):
        if isinstance(v, str):
            return v.strip().lower() in ("true", "1", "yes")
        return bool(v)


class Highlight(BaseModel):
    """A verbatim excerpt of the evidence, plain text only — never HTML.

    `text` MUST be re-verified by the caller (agent.py) as an actual
    substring of the source evidence before use; this schema only
    guarantees shape, not provenance. `start`/`end` are character offsets
    *within `text`* marking the single most significant phrase inside the
    excerpt (e.g. the sentence containing the threat), so the frontend can
    render a <mark> without ever touching dangerouslySetInnerHTML.
    """
    text: str = ""
    start: int = 0
    end: int = 0

    @field_validator("start", "end", mode="before")
    @classmethod
    def _clamp_offset(cls, v):
        return _clamp_int(v, 0, 10_000, 0)


class ForensicAnalysis(BaseModel):
    summary: str = "Analysis complete"
    key_findings: List[str] = Field(default_factory=list)
    entities: Entities = Field(default_factory=Entities)
    highlight: Highlight = Field(default_factory=Highlight)
    anomalies: List[Anomaly] = Field(default_factory=list)
    timeline: List[TimelineEvent] = Field(default_factory=list)

    @field_validator("key_findings", mode="before")
    @classmethod
    def _coerce_findings(cls, v):
        return _as_str_list(v)


# ── FP/TP case verdict (fp_tp_scorer.py: score_case) ────────────────────────

class FpTpFactors(BaseModel):
    factors_for_tp: List[str] = Field(default_factory=list)
    factors_for_fp: List[str] = Field(default_factory=list)
    deciding_factor: str = ""

    @field_validator("factors_for_tp", "factors_for_fp", mode="before")
    @classmethod
    def _coerce(cls, v):
        return _as_str_list(v)


class SeverityBreakdown(BaseModel):
    indicator_risk: int = 0
    behavioral_risk: int = 0
    contextual_risk: int = 0

    @field_validator("indicator_risk", "behavioral_risk", "contextual_risk", mode="before")
    @classmethod
    def _clamp(cls, v):
        return _clamp_int(v, 0, 100, 0)


class CaseVerdict(BaseModel):
    verdict: CaseVerdictValue = "FP"
    confidence: int = 50
    risk_level: RiskLevel = "low"
    case_summary: str = "Analysis complete"
    reasoning: str = ""
    fp_tp_factors: FpTpFactors = Field(default_factory=FpTpFactors)
    recommended_actions: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    iocs: List[str] = Field(default_factory=list)
    threat_actor_profile: Optional[str] = None
    severity_breakdown: SeverityBreakdown = Field(default_factory=SeverityBreakdown)
    # Set only when verdict is NEEDS_REVIEW (see fp_tp_scorer.score_case's
    # post-processing, not the LLM itself — this is a deterministic check
    # on confidence/evidence, not something the model decides on its own).
    # Explains exactly why neither TP nor FP won convincingly.
    review_reason: Optional[str] = None

    @field_validator("verdict", mode="before")
    @classmethod
    def _normalize_verdict(cls, v):
        v = str(v).strip().upper().replace(" ", "_").replace("-", "_")
        return v if v in ("TP", "FP", "NEEDS_REVIEW") else "FP"

    @field_validator("risk_level", mode="before")
    @classmethod
    def _normalize_risk(cls, v):
        v = str(v).strip().lower()
        return v if v in ("critical", "high", "medium", "low", "clean") else "low"

    @field_validator("confidence", mode="before")
    @classmethod
    def _clamp_confidence(cls, v):
        return _clamp_int(v, 0, 100, 50)

    @field_validator("recommended_actions", "mitre_techniques", "iocs", mode="before")
    @classmethod
    def _coerce_lists(cls, v):
        return _as_str_list(v)


# ── Single-indicator verdict (fp_tp_scorer.py: score_single) ────────────────

class SingleIndicatorVerdict(BaseModel):
    verdict: Verdict = "FP"
    confidence: int = 50
    risk_level: RiskLevel = "low"
    reasoning: str = ""
    recommended_action: str = "Continue monitoring"
    mitre_technique: Optional[str] = None
    indicators_of_compromise: List[str] = Field(default_factory=list)

    @field_validator("verdict", mode="before")
    @classmethod
    def _normalize_verdict(cls, v):
        v = str(v).strip().upper()
        return v if v in ("TP", "FP") else "FP"

    @field_validator("risk_level", mode="before")
    @classmethod
    def _normalize_risk(cls, v):
        v = str(v).strip().lower()
        return v if v in ("critical", "high", "medium", "low", "clean") else "low"

    @field_validator("confidence", mode="before")
    @classmethod
    def _clamp_confidence(cls, v):
        return _clamp_int(v, 0, 100, 50)

    @field_validator("indicators_of_compromise", mode="before")
    @classmethod
    def _coerce_list(cls, v):
        return _as_str_list(v)
