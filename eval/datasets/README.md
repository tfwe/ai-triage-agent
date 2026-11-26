# Public-dataset evaluation

The golden set in `eval/golden_dataset.json` is synthetic. This directory holds a
second evaluation built from published intrusion-detection datasets, so the
agent's numbers can be compared against something it had no hand in creating.

| File | Source | What it contributes |
|---|---|---|
| `cicids2017.json` | CIC-IDS2017 (Sharafaldin, Habibi Lashkari, Ghorbani, 2018) | Host compromises and C2 infrastructure |
| `nf-bot-iot.json` | NF-BoT-IoT, the NetFlow export of Bot-IoT (Koroniotis et al., 2019) | Internal hosts running attacks |
| `public.json` | merger of the two | the file the eval scores |

## Where the data comes from

- CIC-IDS2017: the labelled flow CSVs that keep source and destination
  addresses, mirrored at https://huggingface.co/datasets/bvk/CICIDS-2017
  (`monday.csv` … `friday.csv`, about 810 MB). Canonical page:
  https://www.unb.ca/cic/datasets/ids-2017.html
- NF-BoT-IoT: https://huggingface.co/datasets/Mireu-Lab/UNSW-NB15
  (`Archives/NF-UNSW-NB15.zip`, `data/NF-BoT-IoT.csv`, about 50 MB). The
  original Bot-IoT dataset is published by UNSW Canberra.

Neither archive is committed here. Download them, then rebuild:

```bash
python -m eval.load_cicids --src ~/data/cicids2017 --cases-root data/public/cases
python -m eval.load_botiot  --src ~/data/nf-unsw/NF-UNSW-NB15/data
python -m eval.merge_datasets eval/datasets/cicids2017.json eval/datasets/nf-bot-iot.json
```

## How labels are derived

No case is hand-labelled. Each loader applies one documented policy to the
dataset's own per-flow labels, in `LABELLING_RULES` at the top of the module:

- **CIC-IDS2017.** An internal address whose outbound flows are labelled
  `BOTNET` is a compromised host: `ISOLATE_HOST`. An external address that
  receives bot flows from several internal hosts is C2: `BLOCK_IP`. An address
  that only ever appears in `BENIGN` flows is `IGNORE`. Everything else (a
  victim of a flood, the NAT gateway that carries every attack flow, a mixed
  record) is dropped as ambiguous.
- **NF-BoT-IoT.** An address that sources attack-labelled flows (≥5 flows and
  ≥50% of its traffic) is an attacker. Inside the perimeter that is a
  compromised host (`ISOLATE_HOST`); outside it is a threat source
  (`BLOCK_IP`). Benign-only addresses are `IGNORE`.

The label columns are dropped before anything is written to a database, so the
agent cannot read the answer.

## Alerts

Both datasets ship flows, not alerts, so each case database is built by a
deterministic flow detector (`detector_alerts` in `eval/load_cicids.py`):
scan-shaped egress, repeated connections to one service port, high-rate
small-packet traffic, inbound floods, and multi-host beacon receivers. The
detector reads flow shape only. Benign high-volume hosts trip it too, which is
what makes the false-positive rate measurable rather than assumed.

A malicious case is kept only if the detector fired for it; a benign case is
kept either way.

## Splits

Addresses are split `dev` / `holdout` by a hash of the address, so the split is
deterministic and independent of the labels. The agent's system prompt was
revised once on the dev split; the holdout numbers are the reported ones.

## Known limits

- CIC-IDS2017 rewrites the attacker's source address to the border gateway
  (172.16.0.1), so external attackers are only observable as the destination of
  bot flows. That is why this half of the corpus has one `BLOCK_IP` case.
- Bot-IoT is a laboratory capture: every address is RFC1918 and there are no
  timestamps in the NetFlow export, so `timestamp` is NULL in those databases.
- The case counts are small (28 in total). These numbers are indicative, not a
  benchmark.
- Bot-IoT victim mislabelling: the fold policy's source-first rule, together
  with NetFlow reverse and response flows that carry attack labels, marks
  receiving victims as compromised. Holdout victims include 192.168.100.3,
  192.168.100.6 and 192.168.100.148. A model that correctly treats a victim
  as benign scores wrong under the current labels, while a model that follows
  the label scores as correct even though it misreads the victim. Every
  committed holdout score was produced against these labels.
- The system prompt's receiver-is-victim IGNORE rule contradicts its
  BLOCK_IP flow rule for internal scanners. The two holdout cases that loop
  to context exhaustion, BOTIOT-192-168-100-148 and BOTIOT-192-168-100-6,
  are both victim-labelled cases where these two rules collide.