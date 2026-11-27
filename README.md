# ai-triage-agent

A Python agent that triages SOC alerts. It parses vendor logs into a SQLite triage database, lets an LLM query that database through tools, and returns a structured decision (`BLOCK_IP`, `ISOLATE_HOST` or `IGNORE`) with a confidence score, reasoning and a recommended playbook. It is evaluated on a 31-case synthetic golden set against a deterministic rule baseline.

## What it does

- Parses six telemetry families into normalised records: Cisco ASA, ECAR EDR JSONL, Snort/Suricata fast log, Linux (syslog, web access, bash history), Windows Event XML and Zeek JSONL.
- Loads the parser output into a SQLite triage database with four tables.
- Runs an agent loop in which the model queries SQLite itself with a `query_triage_db` tool. No JSON blob is handed to the model. The database is opened read-only.
- Optionally calls `check_ip_reputation` (AbuseIPDB). With no key configured, the tool returns an "unavailable" message and the agent decides from local telemetry.
- Returns a `TriageAction`: `decision`, `confidence_score` (1-100), `reasoning`, `recommended_playbook`.

## Measured results

Source: `eval/results/agent.txt` (agent and rules, same run) and `eval/results/rules-baseline.txt` (rules only). Both score the same 31 cases against the same case databases (dataset digest `2a6921379ee5370b`).

| Metric | Rules | Agent |
|---|---|---|
| Decision accuracy | 31/31 (100.0%) | 28/31 (90.3%) |
| False-positive rate | 0.0% (0/12) | 16.7% (2/12) |
| Missed detections | 0/19 | 0/19 |
| Latency p50 | 1.3 ms | 28.7 s |
| Latency p95 | 3.2 ms | 117.7 s |
| Mean tokens per alert | 0 | 14,763 |
| Evidence recall | n/a | 88.5% |
| Crashed runs | 0 | 0 |

Agent run:

- Model: `ornith-1.5-35b-a3b-apex-i-nanoplus`, served by LM Studio on an RTX 5070 Ti.
- Recorded 2026-11-22T11:44:00Z in `record` mode, at most 12 model turns per case.

Definitions:

- **False positive:** a benign case (expected `IGNORE`) where the agent returned `BLOCK_IP` or `ISOLATE_HOST`.
- **Missed detection:** a malicious case where the agent returned `IGNORE` or no decision. A malicious case escalated with the wrong action (for example `ISOLATE_HOST` for an expected `BLOCK_IP`) is counted as detected, but not as correct.
- **Evidence recall:** the share of each case's expected-evidence signatures that appear in the tool results the agent received.

**Caveat on the rule baseline.** The rule marker list was written and tuned against this same synthetic corpus. Its 100% is an upper bound on this dataset, not an estimate of how rules perform on real alerts. The agent's 90.3% is measured on the same data.

Rule latency varies between runs: the table uses the `agent.txt` run, and `rules-baseline.txt` (a separate rules-only run) reports 2.6 ms p50 and 11.7 ms p95. Treat rule latency as order-of-magnitude only. Replay latencies are not latency measurements (see below).

## How it works

### Pipeline

```
raw vendor logs -> parsers -> processed JSON -> SQLite triage DB -> agent loop -> TriageAction
   data/raw/       parsers/     data/processed/   triage.db           agent/
```

The triage database has four tables:

| Table | Populated from | Contents |
|---|---|---|
| `endpoint_events` | ECAR EDR, Windows Event XML, Linux syslog, web access and bash history | Host-side events, keyed by `source` (`ecar`, `windows_event`, `syslog`, `web_access`, `bash_history`) |
| `network_traffic` | Zeek JSONL | Sessions keyed by `uid`, with source and destination IP and port |
| `alerts` | Snort/Suricata fast log | IDS alerts with sensor, source and destination IP |
| `firewall_events` | Cisco ASA | Firewall messages by host |

Timestamps are kept in their vendor formats and not normalised, so `ORDER BY` across sources is lexicographic.

### Tool loop

1. The agent receives a user message naming the target (host name or IP) and the system prompt, which gives the schema and the decision framework.
2. The model calls `query_triage_db` with a SQL statement. Results are capped at 15 rows; longer results are truncated with a warning. Writes are impossible because the connection is read-only. A guard rejects string hostnames in `src_ip` and `dest_ip`.
3. The model may call `check_ip_reputation` for an IP address.
4. The loop ends when the model returns a JSON object that validates as `TriageAction`. If the model stops calling tools without a valid decision, the loop prompts it to continue. Reaching the turn limit raises an error, which the eval records as a crashed run. The agent default is 25 turns; the eval uses 12.

## Quickstart (offline)

Requirements: Python 3.11+ (the CI job uses 3.11) and Docker, optionally. No model, GPU, API key or network access is needed for these steps.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
```

Build the synthetic corpus and case databases (deterministic):

```bash
python -m eval.corpus_build
```

Run the rule baseline:

```bash
python -m eval.run_evals --rules-only --label rules-check
```

Replay the recorded agent run:

```bash
python -m eval.run_evals --mode replay --label replay-check
```

Each `run_evals` call writes `eval/results/<label>.json` and `.txt`. Always pass `--label`; without it the file is named after the recorded model. Replay should give the same 28/31 decisions and a mean of 14,763.2 tokens per alert as `agent.txt`. Replay does not call a model, so its latency is not a measurement.

Run the test suite (56 tests):

```bash
python -m pytest
```

Docker:

```bash
docker build -t ai-triage-agent .
docker run --rm ai-triage-agent
```

The image builds the corpus at build time. The default command replays the recorded eval offline.

Replay one recorded case through the agent (the target must appear in the recording):

```bash
TRIAGE_DB_PATH=data/cases/CASE-031-BENIGN-PASSWORD-TYPO/triage.db \
  python -m agent.core WS-KORAM-01 --mode replay
```

## Running against your own logs

Parsers read from `./data/raw/` (relative to the repository root) and write to `./data/processed/`. Expected layout by vendor:

| Vendor | Where the parser looks | Format |
|---|---|---|
| Cisco ASA | `data/raw/FW-BO-EDGE/*.log` | ASA syslog lines. Files under that directory are read; any other `.log` file is also scanned. |
| ECAR EDR | `data/raw/<HOST>/ecar.json` | JSONL, one event per line |
| Snort/Suricata | `data/raw/IDS-<name>/*.log` | Fast-log lines |
| Linux syslog | `data/raw/<HOST>/syslog.log` | Syslog lines. The host name is the first path component under `data/raw/`. |
| Linux web | `data/raw/<HOST>/web_access.log` | Combined log format |
| Linux bash | `data/raw/<HOST>/bash_history/<user>` | One command per line. A line of digits prefixed with `#` is an epoch timestamp for the next command. |
| Windows | `data/raw/<HOST>/**/*.xml` | Windows Event XML |
| Zeek | `data/raw/**/{conn,dns,http,ssl,files,dhcp,x509,pe,ocsp}.json` | JSONL, grouped by `uid` |

Malformed lines are quarantined rather than silently dropped by the IDS, ASA, ECAR and Zeek parsers, which write them to `*_quarantine.json` in `data/processed/`. The Linux and Windows parsers skip lines they cannot validate.

Run the parsers, then load the output into the database:

```bash
for m in parsers.asa_parser parsers.ecar_parser parsers.ids_parser \
         parsers.linux_parser parsers.win_event_parser parsers.zeek_parser; do
  python -m "$m"
done
```

```python
import database

counts = database.ingest_processed(
    "data/processed",
    db_path="data/processed/triage.db",
    reset=True,
)
print(counts)
```

Then run the agent against that database:

```bash
TRIAGE_DB_PATH=data/processed/triage.db python -m agent.core <host-or-ip> --mode live
```

The parsers were run end to end on the synthetic corpus in this repository, and the loader produced the same row counts as the corpus build (187, 82, 35 and 28 rows).

### Real vendor export run (pass 8)

The same parsers have also been run end to end on anonymized real vendor exports, and the agent triaged nine targets from that data with the live model. The corpus lives in `data/real-vendor/` (`provenance.json` pins every public source and the anonymization method): Zeek 8.2.2 JSON logs generated locally from 13 public PCAP-ATTACK attack captures, three Windows event log exports from EVTX-ATTACK-SAMPLES, real Linux auth syslog from logpai, and a Suricata alert slice from WRCCDC 2018. Reproduce it with:

```bash
.venv/bin/python scripts/build_real_vendor_corpus.py \
    --raw-dir <pinned raw sources> --zeek-logs-dir <zeek 8.2.2 json logs>
.venv/bin/python scripts/run_real_vendor_pipeline.py \
    --write-results --targets <ip-or-host> ...
```

The pass-8 run ingested 4,996 endpoint events, 165 network sessions and 8,000 IDS alerts into `data/processed-real/real-vendor.db`, then ran the agent on nine targets (seven network IPs, one Windows host, one Linux host). The network IPs are the four highest-volume network participants and the three highest-volume alert sources; the hosts are the Windows C2 host and the Linux host. Parser output counts, quarantine counts, database row counts and the per-target agent decisions are in `eval/results/real-vendor-run.json`; the model recording for those runs is `eval/recordings/real-vendor-ornith.jsonl` (replayable offline). No raw private logs were used or committed; raw sources are pinned by sha256 in `data/real-vendor/provenance.json`.

## Model configuration

`config.py` reads settings from the environment and from `.env` in the working directory. `.env.example` lists every setting with placeholder values.

| Variable | Default | Meaning |
|---|---|---|
| `LLM_PROVIDER` | `ollama` | `ollama` (any OpenAI-compatible local server) or `openai` |
| `LLM_MODE` | `live` | `live`, `record` or `replay` |
| `OLLAMA_BASE_URL` | `http://localhost:11434/v1` | OpenAI-compatible base URL. LM Studio usually listens on port `1234`. |
| `OLLAMA_MODEL` | `devstral-small-2:24b` | Model name for the `ollama` provider |
| `OPENAI_API_KEY` | none | Required when `LLM_PROVIDER=openai` |
| `OPENAI_MODEL` | `gpt-5.6-luna` | Model name for the `openai` provider |
| `ABUSEIPDB_API_KEY` | none | Optional. Without it, `check_ip_reputation` reports the lookup as unavailable. |
| `TRIAGE_DB_PATH` | `data/processed/triage.db` | Database queried by `query_triage_db` |
| `REPLAY_PATH` | `eval/recordings/agent.jsonl` | Recording read in replay mode |
| `RECORD_PATH` | `eval/recordings/agent.jsonl` | Recording written in record mode |

| Mode | Calls the model | Writes a recording | Use |
|---|---|---|---|
| `live` | yes | no | Triage and live evaluation |
| `record` | yes | yes, to `RECORD_PATH` | Captures every request and response. Overwrites the file at that path. |
| `replay` | no | no | Offline reproduction of a recorded run |

Live evaluation against a local server, for example LM Studio:

```bash
LLM_PROVIDER=ollama OLLAMA_BASE_URL=http://localhost:1234/v1 \
  OLLAMA_MODEL=<model-name> python -m eval.run_evals --mode live --label my-run
```

The live path is not exercised in CI: the committed numbers come from one recorded live run on the machine that served the model, and replay reproduces it.

A recording is only valid for the system prompt, tool schemas, database contents and model it was made with. Re-record after changing any of them, or replay will reproduce old decisions.

`docker-compose.yml` runs the image with `.env` loaded, points `OLLAMA_BASE_URL` at `host.docker.internal`, and mounts `data/processed`. It was not run for this README.

## Golden set

`eval/golden_dataset.json` has 31 cases:

| Expected decision | Cases | Meaning |
|---|---|---|
| `ISOLATE_HOST` | 10 | Host compromise |
| `BLOCK_IP` | 9 | External-IP incident |
| `IGNORE` | 12 | Benign or noise |

Each case has a `target_identifier`, a description, an `expected_decision` and a list of `expected_evidence`. There are 52 evidence assertions in total. Each is `{table, where, signature}`:

- `table` and `where` form an SQL condition that must match at least one row in the case's database.
- `signature` must appear in the agent's tool results for that case.

`tests/test_dataset.py` checks that every assertion matches a row in its case database, that case IDs match the corpus, and that the benign cases make the false-positive rate measurable.

The corpus is `eval/corpus/scenarios.json`: vendor-shaped events per case, written by hand and synthetic. `python -m eval.corpus_build` renders them into `data/raw/`, runs the real parsers, and builds one database per case at `data/cases/<case-id>/triage.db` plus a combined database at `data/processed/triage.db`. It is deterministic and makes no model call.

## Where it fails

The committed agent run (`eval/results/agent.json`) has three wrong decisions out of 31. Two are false positives. One is a malicious case escalated with the wrong action.

| Case | Target | Expected | Agent | Kind |
|---|---|---|---|---|
| `CASE-007-EXT-VPN` | `198.51.100.77` | `IGNORE` | `BLOCK_IP` | False positive. A benign failed VPN reconnect by the branch manager was read as hostile. |
| `CASE-023-BENIGN-BACKUP-INTERNAL` | `10.20.4.15` | `IGNORE` | `ISOLATE_HOST` | False positive. A scheduled internal backup push over SMB was read as host compromise. |
| `CASE-019-EXT-MALWARE-CDN` | `193.32.162.44` | `BLOCK_IP` | `ISOLATE_HOST` | Wrong action. An Emotet loader C2 address was escalated to host isolation instead of blocking the IP. |

No malicious case was missed. All wrong decisions are over-escalations or wrong-action escalations.

## Public datasets

The golden set above is synthetic. `eval/datasets/public.json` is a second
evaluation built from two published datasets, so the same harness can be
pointed at data this repository had no hand in creating:

| Source | Cases | Contributes |
|---|---|---|
| CIC-IDS2017 (Sharafaldin et al., 2018) | 18 | 5 host compromises, 1 external C2, 12 benign |
| NF-BoT-IoT, NetFlow export of Bot-IoT (Koroniotis et al., 2019) | 10 | internal hosts running attacks, 1 benign |

Labels come from each dataset's own per-flow columns, folded by a documented
policy and stripped from the databases before the agent sees them. Both ship
flows rather than alerts, so a deterministic flow detector supplies the alert
context (`eval/datasets/README.md` has the policy, the mirrors and the known
limits). Cases are split `dev` / `holdout` by a hash of the address.

Held-out split, 14 cases:

| Metric | Rules | Local 35B | DeepSeek V4.1-Flash | GPT-6-Luna |
|---|---|---|---|---|
| Accuracy | 9/14 (64.3%) | 11/14 (78.6%) | 8/14 (57.1%) | 8/14 (57.1%) |
| False positives | 5/5 | 3/5 | 3/5 | 2/5 |
| Missed detections | 0/9 | 0/9 | 3/9 | 3/9 |
| Latency p50 | 43.4 ms | 47.3 s | 33.1 s | 10.0 s |
| Mean tokens per alert | 0 | 27,616 | 37,299 | 16,158 |
| Cost per 1,000 alerts | $0 | $0 | $2.51 | $2.31 |

Every figure above is quoted from a committed file: the three model columns
from `eval/results/public-holdout-ornith-final.txt` (Local 35B),
`public-holdout-deepseek.txt` and `public-holdout-gpt6luna.txt`, the rules
column from `public-rules-holdout.txt`. The rules latency is model-independent,
so the table takes it from the dedicated rules run rather than re-quoting it
from inside each model run, where cold-start noise moved it between 4.8 and
46.7 ms.

Run-to-run noise is real at temperature 0.1 and is reported rather than
smoothed: over the same holdout cases and databases the local model scored
9/14 and then 11/14, and then 8/14 in a third draw recorded 2026-11-26; all
three runs are committed (`public-holdout-ornith.txt`,
`public-holdout-ornith-final.txt`, `public-holdout-ornith-r3.txt`). Read the
table as one draw each, and the local lead as "level with or slightly ahead",
not as a settled two-case margin. DeepSeek's second holdout run (9/14) was
never committed, so only its single 8/14 draw is on file; the noise claim
therefore rests on the local model's three runs.

The third draw is also the first whose behaviour can be reproduced exactly.
The client passes seed 7 and temperature 0.1, and the three draws taken on
2026-11-26 produced identical decisions and token counts. The two draws on
2026-11-22, 9/14 at 11:11Z and 11/14 at 11:40Z, 29 minutes apart, differed,
so the serving stack of that day did not reproduce seeded trajectories; the
current one does. The earlier r3 attempts were also affected by a serving
problem, now diagnosed and fixed. Two holdout cases,
BOTIOT-192-168-100-148 and BOTIOT-192-168-100-6, deterministically loop to
context exhaustion when the server's prefix cache is warm: a logging proxy
measured 90,884 completion tokens for each of two identical runs, where a
cold server answers the same prompt in about 580 tokens. The uncapped client
timed out three times at 180s per request, and each abandoned attempt left
the server generating a 27 to 39-minute zombie that queued every later case,
so one looping case knocked out the whole suite (6/14 with crashes in the
uncapped draws). The eval client now sends max_tokens 8192, max_retries 0
and a 300s timeout. Healthy turns run 385 to 5,351 completion tokens, so
the cap does not touch them. Under the cap the two looping cases truncate,
receive the harness's "output only the valid JSON schema" nudge, recover,
and answer ISOLATE_HOST correctly, at 53,428 and 36,408 tokens per case.
The 8/14 draw therefore has zero crashed runs, and the crashes in the
earlier draws came from the client and server handling of looping turns,
not from the decisions the model made on the other cases. The holdout
contains victim-mislabelled cases (see `eval/datasets/README.md`), so
"level with or slightly ahead" still describes the local model across three
draws at 8/14, 9/14 and 11/14 against rules at 9/14.

The shape of the result is what matters: on bare flows every approach lands in a narrow band, two hosted models cost $2.31 to $2.51 per 1,000 alerts for no accuracy gain over a model running locally for nothing, and the rule baseline fires on every benign case in the holdout. Evidence recall is 100% for all three models, so the failure is not that they did not look; the flow evidence under-determines the label. The synthetic set, where each case carries alerts, endpoint events and firewall records, is the setting where the agent reaches 90.3%.

The system prompt gained a flow-evidence paragraph between the first synthetic
run and these runs. The dev split absorbed that change; the holdout numbers
above are the ones the prompt was not revised against.

### Reproducing the numbers offline

Replay answers every request from a recorded JSONL: no model, no GPU, no
network, no API key. It regenerates the decisions, the token counts and the
cost column exactly. It does not reproduce the latency column, which is a
wall-clock measurement of the original live runs.

```bash
# one-time: build the case databases from the source archives (both gitignored;
# download instructions and mirrors are in eval/datasets/README.md)
python -m eval.load_cicids --src ~/data/cicids2017 --cases-root data/public/cases
python -m eval.load_botiot  --src ~/data/nf-unsw/NF-UNSW-NB15/data
python -m eval.merge_datasets eval/datasets/cicids2017.json eval/datasets/nf-bot-iot.json

# replay the recorded GPT-6-Luna holdout run
REPLAY_PATH=eval/recordings/public-gpt6luna-holdout.jsonl \
  .venv/bin/python -m eval.run_evals --mode replay \
  --dataset eval/datasets/public.json --split holdout \
  --cases-dir data/public/cases --no-build \
  --price-in 0.10 --price-out 0.50 --label check-gpt6luna
```

Swap `REPLAY_PATH` for any `eval/recordings/public-<model>-<split>.jsonl`:
DeepSeek replay adds `--price-in 0.05 --price-out 0.199`, and the rules
baseline runs with `--rules-only` and no recording
(`.venv/bin/python -m eval.run_evals --mode replay --rules-only ...`). The
recordings for the hosted runs are not committed; `.gitignore` keeps them
out because they replay only alongside the source archives. The first local
holdout run recorded requests under an earlier opening message and replays
only against that prompt revision. The third local holdout run's recording
is committed as `eval/recordings/public-ornith-r3-holdout.jsonl`, together
with the 14 holdout case databases under `data/public/cases/`, so it
replays standalone; CI replays it with 0 mismatches against the results
JSON, latency fields excluded:

```bash
LLM_MODE=replay REPLAY_PATH=eval/recordings/public-ornith-r3-holdout.jsonl \
  .venv/bin/python -m eval.run_evals --mode replay \
  --dataset eval/datasets/public.json --split holdout \
  --cases-dir data/public/cases --no-build --label ci-replay-ornith-r3
```

## Limitations

- The corpus is synthetic and small (31 cases), and the rule baseline was tuned on it. The results do not say how either approach performs on real alerts.
- The public-dataset corpus is small too (28 cases), and CIC-IDS2017 rewrites the attacker's source address to the border gateway, so that half contributes a single `BLOCK_IP` case. NF-BoT-IoT is a laboratory capture with no timestamps in the export.
- The agent's decisions are model output. Nothing here puts an analyst in the loop before an action is taken.
- Each case has its own database rather than a shared store.
- Timestamps are not normalised across vendors.
- AbuseIPDB is optional. Without a key, reputation checks are unavailable.
- No authentication, rate limiting or multi-tenant handling.
- Recordings go stale when the prompt, tool schemas, database contents or model change.

## Bugs fixed in this branch

- Zeek sessions were ingested with the wrong key names, so `network_traffic` rows had NULL `src_ip` and `dest_ip`.
- The combined-log regex captured the referrer as the user agent.
- Bash history events dropped their timestamps.
- The Linux parser derived the hostname from a fixed path index. It now uses the first path component under `data/raw/`.
- Parsers used flat imports that broke under pytest.

## Repository map

| Path | Purpose |
|---|---|
| `config.py` | Settings from environment and `.env` |
| `database.py` | Schema, `ingest_processed` loader and query helper |
| `agent/core.py` | Agent loop, system prompt, `TriageAction` |
| `agent/client.py` | Model clients for live, record and replay modes; `build_client` |
| `agent/tools.py` | `query_triage_db` (read-only) and `check_ip_reputation` |
| `agent/rules.py` | Deterministic rule baseline |
| `parsers/` | One parser per vendor family, plus `schemas.py` |
| `eval/run_evals.py` | Scores rules and agent on the golden set; writes `eval/results/` |
| `eval/corpus_build.py` | Renders the corpus, runs the parsers, builds the databases |
| `eval/golden_dataset.json` | 31 cases with expected decisions and evidence |
| `eval/datasets/` | Public-dataset label files, their README, and the merged case list |
| `eval/load_cicids.py`, `eval/load_botiot.py` | Loaders, labelling policy and flow detector for the public datasets |
| `eval/merge_datasets.py` | Concatenates loader output into one case list |
| `eval/corpus/scenarios.json` | Synthetic vendor-shaped events per case |
| `eval/recordings/agent.jsonl` | 132 recorded request/response exchanges |
| `eval/results/` | `agent.txt`, `rules-baseline.txt` and their JSON versions |
| `tests/` | 56 pytest tests; no network, model or API key needed |
| `Dockerfile`, `docker-compose.yml`, `docker-entrypoint.py` | Container build, compose setup, pre-flight check |
| `.env.example` | Every setting with placeholder values |
| `.github/workflows/ci.yml` | Test job and offline replay job |

## License

MIT, see `LICENSE`.
