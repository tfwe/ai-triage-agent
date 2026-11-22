"""Turn NF-BoT-IoT (UNSW Canberra) NetFlow records into triage cases.

Source: NF-BoT-IoT, the NetFlow v9 export of the Bot-IoT dataset (Koroniotis,
Moustafa, Sitnikova and Turnbull, 2019), as packaged by Sarhan, Layeghy and
Portmann for their NetFlow dataset paper. Mirror used:
https://huggingface.co/datasets/Mireu-Lab/UNSW-NB15 (Archives/NF-UNSW-NB15.zip,
data/NF-BoT-IoT.csv). Label columns are ``Label`` (0/1) and ``Attack``
(Reconnaissance, DoS, DDoS, Theft).

Bot-IoT is a laboratory IoT capture: every address is RFC1918, the four
attackers are 192.168.100.147-150 and the victims are 192.168.100.3-7. The
attacker is therefore identified by role (it sources attack-labelled flows),
not by being routable. There are no timestamps in the NetFlow export, so
``timestamp`` is left NULL in the case databases and the agent has to work
from volume, ports and durations.

Usage:
    python -m eval.load_botiot --src ~/data/nf-unsw/NF-UNSW-NB15/data \
        --out eval/datasets/nf-bot-iot.json
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import os
from collections import Counter, defaultdict

from eval.load_cicids import (
    MAX_ATTACK_FLOWS_PER_TARGET,
    MAX_BENIGN_FLOWS_PER_TARGET,
    MIN_FLOWS_PER_TARGET,
    Target,
    _is_internal,
    _safe_float,
    _safe_int,
    write_case_databases,
)

MIN_ATTACK_FLOWS = 5
MIN_ATTACK_SHARE = 0.5
# Bot-IoT's benign devices are quiet: a home device with 12 flows is still a
# case, while an attacker with the same count is not worth a case.
MIN_BENIGN_FLOWS = 10

LABELLING_RULES = """
attacker: an address with >= MIN_ATTACK_FLOWS attack-labelled flows as source
    and >= MIN_ATTACK_SHARE of its flows labelled as an attack.
    Inside the perimeter that is a compromised host -> ISOLATE_HOST;
    outside it is a threat source -> BLOCK_IP.
benign:   an address whose every flow, in both roles, is Benign -> IGNORE.
anything else (victim of an attack, mixed traffic) -> dropped as ambiguous.
"""

COLUMNS = {
    "src_ip": "IPV4_SRC_ADDR",
    "dst_ip": "IPV4_DST_ADDR",
    "src_port": "L4_SRC_PORT",
    "dst_port": "L4_DST_PORT",
    "protocol": "PROTOCOL",
    "duration": "FLOW_DURATION_MILLISECONDS",
    "in_bytes": "IN_BYTES",
    "out_bytes": "OUT_BYTES",
    "in_pkts": "IN_PKTS",
    "out_pkts": "OUT_PKTS",
    "label": "Label",
    "attack": "Attack",
}


def _iter_rows(src_dir: str):
    paths = [
        os.path.join(src_dir, name)
        for name in sorted(os.listdir(src_dir))
        if name.lower().endswith(".csv") and "bot" in name.lower()
    ]
    if not paths:
        raise FileNotFoundError(f"no NF-BoT-IoT CSV under {src_dir}")
    for path in paths:
        with open(path, newline="", encoding="utf-8", errors="replace") as handle:
            reader = csv.DictReader(handle)
            reader.fieldnames = [field.strip() for field in reader.fieldnames]
            missing = set(COLUMNS.values()) - set(reader.fieldnames)
            if missing:
                raise ValueError(f"{path}: missing columns {sorted(missing)}")
            print(f"  reading {os.path.basename(path)} ...", flush=True)
            for row in reader:
                yield row


def _valid_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address((value or "").strip()))
    except ValueError:
        return None


def _is_attack(row: dict) -> bool:
    attack = (row.get(COLUMNS["attack"]) or "").strip().lower()
    if attack and attack != "normal":
        return True
    return (row.get(COLUMNS["label"]) or "").strip() == "1"


def scan_source(src_dir: str) -> dict[str, Target]:
    targets: dict[str, Target] = {}
    for row in _iter_rows(src_dir):
        src = _valid_ip(row.get(COLUMNS["src_ip"]))
        dst = _valid_ip(row.get(COLUMNS["dst_ip"]))
        if not src or not dst:
            continue
        label = "ATTACK" if _is_attack(row) else "BENIGN"
        for address, role in ((src, "src"), (dst, "dst")):
            target = targets.get(address)
            if target is None:
                target = Target()
                targets[address] = target
            if role == "src":
                target.as_src[label] += 1
            else:
                target.as_dst[label] += 1
            target.count += 1
    return targets


def sample_flows(src_dir: str, wanted: set[str]) -> dict[str, list[dict]]:
    samples: dict[str, list[dict]] = {address: [] for address in wanted}
    benign_seen: Counter = Counter()
    attack_kept: Counter = Counter()

    for row in _iter_rows(src_dir):
        src = _valid_ip(row.get(COLUMNS["src_ip"]))
        dst = _valid_ip(row.get(COLUMNS["dst_ip"]))
        if not src or not dst or (src not in wanted and dst not in wanted):
            continue

        attack = _is_attack(row)
        flow = {
            "ts": None,  # the NetFlow export carries no timestamp
            "src": src,
            "dst": dst,
            "sport": _safe_int(row.get(COLUMNS["src_port"])),
            "dport": _safe_int(row.get(COLUMNS["dst_port"])),
            "proto": str(_safe_int(row.get(COLUMNS["protocol"])) or "tcp"),
            "duration": _safe_float(row.get(COLUMNS["duration"])),
            "fwd_packets": _safe_int(row.get(COLUMNS["in_pkts"])),
            "bwd_packets": _safe_int(row.get(COLUMNS["out_pkts"])),
            "fwd_bytes": _safe_int(row.get(COLUMNS["in_bytes"])),
            "bwd_bytes": _safe_int(row.get(COLUMNS["out_bytes"])),
        }

        for address in {src, dst} & wanted:
            if attack:
                if attack_kept[address] < MAX_ATTACK_FLOWS_PER_TARGET:
                    samples[address].append(flow)
                    attack_kept[address] += 1
                continue
            benign_seen[address] += 1
            stride = max(1, benign_seen[address] // MAX_BENIGN_FLOWS_PER_TARGET)
            if benign_seen[address] % stride == 0 and len(samples[address]) < (
                MAX_BENIGN_FLOWS_PER_TARGET + MAX_ATTACK_FLOWS_PER_TARGET
            ):
                samples[address].append(flow)
    return samples


def classify_target(address: str, target: Target) -> tuple[str | None, str]:
    attacks = target.as_src.get("ATTACK", 0)
    benign = target.as_src.get("BENIGN", 0)
    total_src = attacks + benign
    share = attacks / total_src if total_src else 0.0
    dst_attacks = target.as_dst.get("ATTACK", 0)
    dst_benign = target.as_dst.get("BENIGN", 0)

    if attacks >= MIN_ATTACK_FLOWS and share >= MIN_ATTACK_SHARE:
        if _is_internal(address):
            return "ISOLATE_HOST", (
                f"internal host that sources {attacks} attack-labelled flows "
                f"({share:.0%} of its {total_src} flows): a compromised machine "
                "inside the perimeter"
            )
        return "BLOCK_IP", (
            f"external address that sources {attacks} attack-labelled flows "
            f"({share:.0%} of its {total_src} flows) in the lab capture"
        )
    if attacks == 0 and dst_attacks == 0:
        return "IGNORE", f"address whose {benign + dst_benign} flows are all labelled Benign"
    if dst_attacks and not attacks:
        return None, f"victim: {dst_attacks} attack flows arrive here and none leave"
    return None, f"mixed traffic: {attacks} attack / {benign} benign as source"


def build_cases(targets: dict[str, Target], holdout_fraction: float = 0.5) -> list[dict]:
    buckets: dict[str, list] = defaultdict(list)
    for address, target in targets.items():
        decision, description = classify_target(address, target)
        if decision is None:
            continue
        floor = MIN_FLOWS_PER_TARGET if decision != "IGNORE" else MIN_BENIGN_FLOWS
        if target.count < floor:
            continue
        buckets[decision].append((address, target, decision, description))

    malicious = len(buckets["BLOCK_IP"]) + len(buckets["ISOLATE_HOST"])
    benign_budget = max(malicious, 12)
    benign = sorted(buckets["IGNORE"], key=lambda c: (-c[1].count, c[0]))[:benign_budget]

    cases = []
    for address, target, decision, description in (
        buckets["BLOCK_IP"] + buckets["ISOLATE_HOST"] + benign
    ):
        split = (
            "holdout"
            if int(hashlib.sha256(address.encode()).hexdigest(), 16) % 100 < holdout_fraction * 100
            else "dev"
        )
        cases.append(
            {
                "id": f"BOTIOT-{address.replace('.', '-')}",
                "target_identifier": address,
                "expected_decision": decision,
                "description": description,
                "split": split,
                "flows": [],
                "expected_evidence": [
                    {
                        "table": "network_traffic",
                        "where": f"src_ip = '{address}' OR dest_ip = '{address}'",
                        "signature": address,
                    }
                ],
            }
        )
    cases.sort(key=lambda case: case["id"])
    return cases


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Build NF-BoT-IoT triage cases.")
    parser.add_argument("--src", default=os.path.expanduser("~/data/nf-unsw/NF-UNSW-NB15/data"))
    parser.add_argument("--out", default="eval/datasets/nf-bot-iot.json")
    parser.add_argument("--cases-root", default="data/public/cases")
    parser.add_argument("--holdout", type=float, default=0.5)
    args = parser.parse_args(argv)

    print(f"[botiot] scanning {args.src}")
    targets = scan_source(args.src)
    cases = build_cases(targets, args.holdout)
    wanted = {case["target_identifier"] for case in cases}
    print(f"[botiot] sampling flows for {len(wanted)} cases ...", flush=True)
    samples = sample_flows(args.src, wanted)
    for case in cases:
        case["flows"] = samples.get(case["target_identifier"], [])
    alert_counts = write_case_databases(cases, args.cases_root)
    kept = [
        case for case in cases
        if alert_counts.get(case["id"], 0) > 0 or case["expected_decision"] == "IGNORE"
    ]
    dropped = len(cases) - len(kept)
    cases = kept

    public = [{k: v for k, v in case.items() if k != "flows"} for case in cases]
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(public, handle, indent=2)

    print(f"[botiot] {len(cases)} cases -> {args.out}")
    print(f"  decisions: {dict(Counter(c['expected_decision'] for c in cases))}")
    print(f"  splits:    {dict(Counter(c['split'] for c in cases))}")
    print(f"  dropped (no detector alert fired): {dropped}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())