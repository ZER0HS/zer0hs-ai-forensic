"""
Runs the labeled benchmark set in tests/benchmark/ through the real
analysis pipeline and reports accuracy, precision, recall, and a
confusion matrix.

This calls the same functions main.py's /analyze route calls, not the
HTTP layer, so it runs offline without needing the server up. It does
NOT call feedback.save_analysis() — a benchmark run should never write
into the live case-history store real usage relies on.

Usage:
    cd backend
    python scripts/run_benchmark.py [--limit N] [--markdown out.md]

Requires the same environment as the running app: LLM_PROVIDER (defaults
to ollama, the mode this was designed to be run in), and the threat-intel
API keys in .env if you want the threat-intel layer genuinely exercised
rather than reporting every indicator as "not configured."

IMPORTANT about what this number does and doesn't mean: tests/benchmark/
is a small, synthetic set constructed for this project, not a large
real-world phishing corpus. It's useful for catching regressions and for
giving a concrete, reproducible number instead of no number at all — it
is not a claim about real-world detection accuracy at scale. See
THREAT_MODEL.md and the README's performance section for that caveat
stated in full.
"""
import argparse
import asyncio
import io
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dotenv import load_dotenv

load_dotenv()

from extractor import extract_indicators
from knowledge_base import get_relevant_patterns
from parser import extract_text
from rule_engine import run_rules, shortcircuit_forensic, shortcircuit_verdict
from sandbox import check_all_hashes
from threat_intel import check_all_indicators

BENCHMARK_DIR = Path(__file__).resolve().parents[1] / "tests" / "benchmark"


class _FileFromBytes:
    """Minimal stand-in for FastAPI's UploadFile — parser.extract_text()
    only ever calls .filename and awaits .read()."""

    def __init__(self, path: Path):
        self.filename = path.name
        self._content = path.read_bytes()

    async def read(self):
        return self._content


async def run_one_case(path: Path) -> dict:
    file = _FileFromBytes(path)
    raw_text, eml_data = await extract_text(file)

    indicators = extract_indicators(raw_text)
    if eml_data and eml_data.get("routing_ips"):
        for ip in eml_data["routing_ips"]:
            if ip not in indicators["ips"] and ip not in indicators.get("private_ips", []):
                indicators["ips"].append(ip)

    attachments = eml_data.get("attachments", []) if eml_data else []
    threat_results, hash_results = await asyncio.gather(
        check_all_indicators(indicators),
        check_all_hashes(attachments),
    )

    rule_findings = run_rules(raw_text, indicators, threat_results, hash_results, attachments)
    patterns = get_relevant_patterns(raw_text, indicators)

    override = rule_findings.get("verdict_override")
    if override:
        verdict = shortcircuit_verdict(rule_findings)
        used_llm = False
    else:
        # Imported lazily so a benchmark run against a provider that isn't
        # configured fails on the specific case, not at import time.
        from combined_analysis import run_combined_analysis

        combined = await run_combined_analysis(
            raw_text, indicators, threat_results, rule_findings, patterns, eml_data
        )
        verdict = combined["verdict"]
        used_llm = True

    return {
        "predicted": verdict["verdict"],
        "confidence": verdict["confidence"],
        "used_llm": used_llm,
        "rule_score": rule_findings.get("rule_score", 0),
    }


async def main(limit: int | None, markdown_path: str | None):
    manifest = json.loads((BENCHMARK_DIR / "manifest.json").read_text(encoding="utf-8"))
    if limit:
        manifest = manifest[:limit]

    results = []
    t0 = time.time()
    for i, case in enumerate(manifest, 1):
        path = BENCHMARK_DIR / case["filename"]
        print(f"[{i}/{len(manifest)}] {case['filename']} ... ", end="", flush=True)
        t_case = time.time()
        outcome = await run_one_case(path)
        elapsed = time.time() - t_case
        correct = outcome["predicted"] == case["verdict"]
        label = "OK" if correct else ("REVIEW" if outcome["predicted"] == "NEEDS_REVIEW" else "WRONG")
        print(f"predicted={outcome['predicted']} actual={case['verdict']} "
              f"{label} ({elapsed:.1f}s, llm={outcome['used_llm']})")
        results.append({**case, **outcome, "correct": correct})

    total_time = time.time() - t0

    # NEEDS_REVIEW is scored out of the strict TP/FP confusion matrix
    # entirely — it's neither a hit nor a miss against a binary ground
    # truth, it's the system correctly declining to guess. Reported
    # separately below rather than silently counted as wrong.
    reviewed = [r for r in results if r["predicted"] == "NEEDS_REVIEW"]
    scored   = [r for r in results if r["predicted"] != "NEEDS_REVIEW"]

    tp = sum(1 for r in scored if r["verdict"] == "TP" and r["predicted"] == "TP")
    fn = sum(1 for r in scored if r["verdict"] == "TP" and r["predicted"] == "FP")
    tn = sum(1 for r in scored if r["verdict"] == "FP" and r["predicted"] == "FP")
    fp = sum(1 for r in scored if r["verdict"] == "FP" and r["predicted"] == "TP")

    n = len(scored)
    accuracy  = (tp + tn) / n * 100 if n else 0
    precision = tp / (tp + fp) * 100 if (tp + fp) else 0
    recall    = tp / (tp + fn) * 100 if (tp + fn) else 0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) else 0

    print("\n" + "=" * 60)
    print(f"Cases: {len(results)} ({len(reviewed)} flagged NEEDS_REVIEW, "
          f"scored against {n})   Time: {total_time:.1f}s")
    print(f"Confusion matrix — predicted TP / predicted FP")
    print(f"  actual TP:  {tp:>3}          {fn:>3}")
    print(f"  actual FP:  {fp:>3}          {tn:>3}")
    print(f"Accuracy:  {accuracy:.1f}%")
    print(f"Precision: {precision:.1f}%")
    print(f"Recall:    {recall:.1f}%")
    print(f"F1:        {f1:.1f}%")

    wrong = [r for r in scored if not r["correct"]]
    if wrong:
        print("\nMissed cases:")
        for r in wrong:
            print(f"  {r['filename']}: predicted {r['predicted']}, actual {r['verdict']} ({r['category']})")
    if reviewed:
        print("\nFlagged for human review (excluded from the confusion matrix above):")
        for r in reviewed:
            print(f"  {r['filename']}: actual {r['verdict']} ({r['category']})")

    if markdown_path:
        md = f"""| Metric | Value |
|---|---|
| Cases | {len(results)} |
| Flagged NEEDS_REVIEW | {len(reviewed)} |
| Scored (TP/FP only) | {n} |
| Accuracy | {accuracy:.1f}% |
| Precision | {precision:.1f}% |
| Recall | {recall:.1f}% |
| F1 | {f1:.1f}% |
| True positives | {tp} |
| False positives | {fp} |
| True negatives | {tn} |
| False negatives | {fn} |
"""
        Path(markdown_path).write_text(md, encoding="utf-8")
        print(f"\nMarkdown table written to {markdown_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=None, help="Only run the first N cases (for a quick smoke run)")
    parser.add_argument("--markdown", type=str, default=None, help="Write a ready-to-paste Markdown table to this path")
    args = parser.parse_args()
    asyncio.run(main(args.limit, args.markdown))
