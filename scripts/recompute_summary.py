"""Recompute a result file's `summary` block from its own grading rows.

The per-case rows are the primary record of a run (they carry the decisions,
the per-assertion checks and the judge verdicts). The summary is a pure view
derived from them, so when the aggregation code changes — as it did for
absence grading, which moved from per-case to per-assertion counting — the
summary of an already-committed run can be recomputed without re-running the
model or touching any grading row.

The transformation is exactly what `eval.run_evals.summarise_v2` does at run
time; this script exists so the change is auditable rather than a hand edit,
and it refuses to run unless the result file's dataset hash matches the
dataset currently on disk.

Usage:
    python scripts/recompute_summary.py eval/results/real-vendor-holdout-ij-r1.json [...]
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from eval.run_evals import summarise_v2


def dataset_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def recompute(result_path: Path, dataset_path: Path) -> dict:
    result = json.loads(result_path.read_text())
    dataset = json.loads(dataset_path.read_text())

    recorded_sha = result.get("dataset_sha256")
    current_sha = dataset_sha256(dataset_path)
    if recorded_sha and not current_sha.startswith(recorded_sha):
        raise SystemExit(
            f"{result_path.name}: dataset hash {recorded_sha[:12]} does not match "
            f"{dataset_path.name} {current_sha[:12]} — refusing to recompute"
        )

    before = result["summary"]
    result["summary"] = summarise_v2(result["per_case"], dataset)
    result["summary_recomputed_from"] = (
        "per_case rows of this file; absence recall counted per judge verdict "
        "(summarise_v2), no model calls"
    )
    result_path.write_text(json.dumps(result, indent=2) + "\n")
    return {"file": result_path.name, "before": before["assertion_recall"]["absence"],
            "after": result["summary"]["assertion_recall"]["absence"]}


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    dataset_path = Path("eval/datasets/real-vendor-holdout.json")
    for arg in argv:
        print(json.dumps(recompute(Path(arg), dataset_path)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
