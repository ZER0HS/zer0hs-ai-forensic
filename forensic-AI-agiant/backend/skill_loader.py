"""Loads a methodology "skill" file once and caches it in memory.

Both agent.py and fp_tp_scorer.py load the same forensic_analysis_skill.md
as their system prompt instead of maintaining separate inline strings — see
that file for why (evidence-grounding, anti-injection, plain-text-citation
rules that both prompts must share).
"""
from functools import lru_cache
from pathlib import Path

SKILLS_DIR = Path(__file__).parent / "skills"


@lru_cache(maxsize=None)
def load_skill(name: str) -> str:
    path = SKILLS_DIR / name
    if not path.exists():
        raise FileNotFoundError(
            f"Skill file '{name}' not found in {SKILLS_DIR}. "
            "This is required — agent.py and fp_tp_scorer.py have no "
            "inline fallback prompt."
        )
    return path.read_text(encoding="utf-8")
