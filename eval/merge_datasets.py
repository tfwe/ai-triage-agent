"""Merge loader outputs into one dataset the eval can score in a single run.

    python -m eval.merge_datasets --out eval/datasets/public.json \
        eval/datasets/cicids2017.json eval/datasets/nf-bot-iot.json

Every loader writes its case databases under the same ``--cases-root``, so the
merged list only has to concatenate the label files and assert that no id is
claimed twice.
"""
from __future__ import annotations

import argparse
import json
import os
from collections import Counter


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Merge dataset label files.")
    parser.add_argument("inputs", nargs="+")
    parser.add_argument("--out", default="eval/datasets/public.json")
    args = parser.parse_args(argv)

    cases: list[dict] = []
    seen = set()
    sources = Counter()
    for path in args.inputs:
        with open(path, encoding="utf-8") as handle:
            chunk = json.load(handle)
        for case in chunk:
            if case["id"] in seen:
                raise SystemExit(f"duplicate case id: {case['id']}")
            seen.add(case["id"])
            case = dict(case)
            case["source_dataset"] = os.path.basename(path).replace(".json", "")
            cases.append(case)
        sources[os.path.basename(path)] = len(chunk)

    cases.sort(key=lambda case: case["id"])
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(cases, handle, indent=2)

    print(f"[merge] {len(cases)} cases -> {args.out}")
    print(f"  per source: {dict(sources)}")
    print(f"  decisions:  {dict(Counter(c['expected_decision'] for c in cases))}")
    print(f"  splits:     {dict(Counter(c['split'] for c in cases))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())