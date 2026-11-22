# Synthetic evidence corpus

`scenarios.json` is the input side of the eval: one block per golden-set case,
holding the vendor-shaped events an analyst would see for that alert. It is
hand-written and synthetic. There is no customer data, no real hostname and no
real credential in it.

`python -m eval.corpus_build` renders these events into vendor-format log files
under `data/raw/`, runs the actual parsers in `parsers/`, and builds
`data/processed/triage.db`. That means the eval exercises the parsing pipeline
rather than loading JSON straight into SQLite, so a parser regression shows up
as a failed case.

Determinism: the file is static, `repeat` templates expand by index, and no
timestamps come from the clock. Rebuilding on any machine produces the same
database.

Case ids match `eval/golden_dataset.json` one-to-one; `tests/test_dataset.py`
fails if either side gains a case the other lacks.