"""Turn CIC-IDS2017 labelled flows into triage cases and per-case databases.

Source: CIC-IDS2017 (Sharafaldin, Habibi Lashkari and Ghorbani, 2018), the
labelled flow CSVs that keep source and destination IPs. The mirror used here
is https://huggingface.co/datasets/bvk/CICIDS-2017 (monday..friday.csv), which
is a re-export of UNB's GeneratedLabelledFlows archive; the UNB page is
https://www.unb.ca/cic/datasets/ids-2017.html.

What this script does, deterministically:

1. Streams every flow row once, decoding the decimal IP columns to addresses.
2. Attributes each flow to both its source and its destination address, keeping
   a bounded, evenly strided sample of rows per address.
3. Derives the expected decision for each address from the dataset's own labels
   with the fixed rules in ``LABELLING_RULES``. No case is hand-labelled.
4. Splits addresses into ``dev`` and ``holdout`` by a hash of the address, so
   prompt tuning can use one half and the reported number the other.
5. Writes one SQLite triage database per case and the dataset JSON.

The Label column is dropped before anything is written to a database: the
agent must reason from flow behaviour, not read the answer.

Usage:
    python -m eval.load_cicids --src ~/data/cicids2017 --out eval/datasets/cicids2017.json

Reproducing the source files: download monday..friday.csv from the mirror
above (about 810 MB in total) into a directory, then pass that directory.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import os
import sys
from collections import Counter, defaultdict

import database

DAY_FILES = ("monday.csv", "tuesday.csv", "wednesday.csv", "thursday.csv", "friday.csv")

# Flow sampling per case database. Attack-labelled flows are always kept
# (they are what a flow collector would alert on); benign flows are evenly
# strided down to the cap so one case cannot drown the context window.
MAX_BENIGN_FLOWS_PER_TARGET = 4000
MAX_ATTACK_FLOWS_PER_TARGET = 1000
# Or fewer than this many flows is too thin to reason about; the address is skipped.
MIN_FLOWS_PER_TARGET = 40

# The dataset's labels, folded into the three triage decisions. This is the
# whole ground-truth policy; it is applied mechanically, per address.
LABELLING_RULES = """
BOTNET on the source of an internal address  -> that host is infected: ISOLATE_HOST.
BOTNET (or BOTNET - ATTEMPTED) as the destination of an
    external address with >= MIN_C2_FLOWS flows -> C2 infrastructure: BLOCK_IP.
Any attack label on the source of an external address -> BLOCK_IP.
Only BENIGN flows for every role          -> IGNORE.
Anything else (a victim of a flood, a NAT gateway that carries attack
    labels, a mixed record)               -> dropped as ambiguous.
"""

# CIC-IDS2017 spells the bot labels this way, and NAT rewrites the attacker's
# source address to the border gateway, so external attackers are only
# observable as the destination of the bot flows they serve.
BOT_LABELS = {"BOTNET", "BOTNET - ATTEMPTED"}
MIN_C2_FLOWS = 20

ATTACK_LABELS = {
    "FTP-PATATOR",
    "SSH-PATATOR",
    "FTP-PATATOR - ATTEMPTED",
    "SSH-PATATOR - ATTEMPTED",
    "DOS HULK",
    "DOS GOLDENEYE",
    "DOS SLOWLORIS",
    "DOS SLOWHTTPTEST",
    "HEARTBLEED",
    "DDOS",
    "WEB ATTACK - BRUTE FORCE",
    "WEB ATTACK - XSS",
    "WEB ATTACK - SQL INJECTION",
    "INFILTRATION",
    "PORTSCAN",
    "BOTNET",
    "BOTNET - ATTEMPTED",
}

NETWORK_COLUMNS = {
    "src_ip": "Src IP dec",
    "dst_ip": "Dst IP dec",
    "src_port": "Src Port",
    "dst_port": "Dst Port",
    "protocol": "Protocol",
    "timestamp": "Timestamp",
    "duration": "Flow Duration",
    "fwd_packets": "Total Fwd Packet",
    "bwd_packets": "Total Bwd packets",
    "fwd_bytes": "Total Length of Fwd Packet",
    "bwd_bytes": "Total Length of Bwd Packet",
    "label": "Label",
}


def _int_to_ip(value: str) -> str | None:
    try:
        number = int(float(value))
    except (TypeError, ValueError):
        return None
    if not 0 <= number <= 2**32 - 1:
        return None
    return str(ipaddress.IPv4Address(number))


def _timestamp(value):
    """CIC-IDS2017 stamps flows with a capture-relative MM:SS.s offset."""
    text = (value or "").strip()
    if not text:
        return None
    parts = text.split(":")
    if 2 <= len(parts) <= 3:
        try:
            numbers = [float(part) for part in parts]
        except ValueError:
            numbers = []
        if numbers:
            seconds = 0.0
            for number in numbers:
                seconds = seconds * 60 + number
            return round(seconds, 3)

    from datetime import datetime

    for fmt in ("%d/%m/%Y %H:%M", "%d/%m/%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(text, fmt).timestamp()
        except ValueError:
            continue
    return None


def _is_internal(address: str) -> bool:
    return ipaddress.ip_address(address).is_private


def _normalise_label(label: str) -> str:
    cleaned = " ".join(label.strip().upper().split())
    # The dataset spells slow http test and web attacks inconsistently.
    cleaned = cleaned.replace("SLOWHTTPTEST", "SLOWHTTPTEST").replace("WEB ATTACK \u2013", "WEB ATTACK -")
    return cleaned


class Target:
    __slots__ = ("as_src", "as_dst", "flows", "count", "first_ts")

    def __init__(self):
        self.as_src: Counter = Counter()
        self.as_dst: Counter = Counter()
        self.flows: list[dict] = []
        self.count = 0
        self.first_ts = None


def _iter_rows(src_dir: str):
    for name in DAY_FILES:
        path = os.path.join(src_dir, name)
        if not os.path.exists(path):
            raise FileNotFoundError(path)
        with open(path, newline="", encoding="utf-8", errors="replace") as handle:
            reader = csv.DictReader(handle)
            reader.fieldnames = [field.strip() for field in reader.fieldnames]
            missing = {v for v in NETWORK_COLUMNS.values() if v not in reader.fieldnames}
            if missing:
                raise ValueError(f"{name}: missing columns {sorted(missing)}")
            print(f"  reading {name} ...", flush=True)
            for row in reader:
                yield row


def scan_source(src_dir: str) -> dict[str, Target]:
    """Pass 1: count flows and labels per address. Samples nothing yet."""
    targets: dict[str, Target] = {}

    for row in _iter_rows(src_dir):
        src = _int_to_ip(row.get("Src IP dec"))
        dst = _int_to_ip(row.get("Dst IP dec"))
        if not src or not dst:
            continue
        label = _normalise_label(row.get("Label", ""))

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
    """Pass 2: keep every attack-labelled flow plus a strided benign sample."""
    samples: dict[str, list[dict]] = {address: [] for address in wanted}
    benign_seen: Counter = Counter()
    attack_kept: Counter = Counter()

    for row in _iter_rows(src_dir):
        src = _int_to_ip(row.get("Src IP dec"))
        dst = _int_to_ip(row.get("Dst IP dec"))
        if not src or not dst:
            continue
        if src not in wanted and dst not in wanted:
            continue

        label = _normalise_label(row.get("Label", ""))
        flow = {
            "ts": _timestamp(row.get("Timestamp", "")),
            "src": src,
            "dst": dst,
            "sport": _safe_int(row.get("Src Port")),
            "dport": _safe_int(row.get("Dst Port")),
            "proto": (row.get("Protocol") or "tcp").strip().lower(),
            "duration": _safe_float(row.get("Flow Duration")),
            "fwd_packets": _safe_int(row.get("Total Fwd Packet")),
            "bwd_packets": _safe_int(row.get("Total Bwd packets")),
            "fwd_bytes": _safe_int(row.get("Total Length of Fwd Packet")),
            "bwd_bytes": _safe_int(row.get("Total Length of Bwd Packet")),
        }

        for address in {src, dst} & wanted:
            if label != "BENIGN":
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

    for address in samples:
        samples[address].sort(key=lambda flow: (flow["ts"] or 0, flow["dport"] or 0))
    return samples


def _safe_int(value):
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _safe_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def classify_target(address: str, target: Target) -> tuple[str | None, str]:
    """Apply LABELLING_RULES. Returns (decision, human description)."""
    src_labels = {
        _normalise_label(label): count for label, count in target.as_src.items() if label
    }
    dst_labels = {
        _normalise_label(label): count for label, count in target.as_dst.items() if label
    }
    all_labels = set(src_labels) | set(dst_labels)
    internal = _is_internal(address)

    non_benign_src = {label for label in src_labels if label != "BENIGN" and label in ATTACK_LABELS}
    non_benign_dst = {label for label in dst_labels if label != "BENIGN" and label in ATTACK_LABELS}

    if internal and any(label in BOT_LABELS for label in src_labels):
        bot_hits = sum(src_labels.get(label, 0) for label in BOT_LABELS)
        return "ISOLATE_HOST", (
            f"internal host whose outbound flows are labelled BOTNET "
            f"({bot_hits} flows): a bot infection on the host"
        )
    if not internal and sum(dst_labels.get(label, 0) for label in BOT_LABELS) >= MIN_C2_FLOWS:
        bot_hits = sum(dst_labels.get(label, 0) for label in BOT_LABELS)
        return "BLOCK_IP", (
            f"external address that receives {bot_hits} bot flows from internal "
            f"hosts: C2 infrastructure"
        )
    if not internal and non_benign_src:
        labels = ", ".join(sorted(non_benign_src))
        return "BLOCK_IP", (
            f"external address that sources attack traffic labelled {labels} "
            f"against the monitored network"
        )
    if not internal and non_benign_dst and internal is False:
        # An external address that is only a destination of attack flows is a
        # victim or a relay: ambiguous for triage, so it is dropped.
        pass
    if not all_labels or all_labels == {"BENIGN"}:
        return "IGNORE", (
            f"address that appears only in BENIGN flows "
            f"({sum(src_labels.values()) + sum(dst_labels.values())} flows)"
        )
    return None, f"ambiguous label mixture: src={sorted(src_labels)} dst={sorted(dst_labels)}"


def build_cases(targets: dict[str, Target], holdout_fraction: float = 0.5) -> list[dict]:
    candidates = []
    for address, target in targets.items():
        if target.count < MIN_FLOWS_PER_TARGET:
            continue
        decision, description = classify_target(address, target)
        if decision is None:
            continue
        candidates.append((address, target, decision, description))

    by_decision: dict[str, list] = defaultdict(list)
    for candidate in candidates:
        by_decision[candidate[2]].append(candidate)

    # Benign addresses vastly outnumber malicious ones; keep a deterministic
    # slice so neither decision dominates the score.
    malicious_count = len(by_decision["BLOCK_IP"]) + len(by_decision["ISOLATE_HOST"])
    benign_budget = max(malicious_count, 12)
    benign = sorted(by_decision["IGNORE"], key=lambda c: (-c[1].count, c[0]))[:benign_budget]

    selected = by_decision["BLOCK_IP"] + by_decision["ISOLATE_HOST"] + benign
    selected.sort(key=lambda c: c[0])

    cases = []
    for address, target, decision, description in selected:
        bucket = "holdout" if int(hashlib.sha256(address.encode()).hexdigest(), 16) % 100 < holdout_fraction * 100 else "dev"
        case_id = f"CIC-{address.replace('.', '-')}"
        cases.append(
            {
                "id": case_id,
                "target_identifier": address,
                "expected_decision": decision,
                "description": description,
                "split": bucket,
                "flows": target.flows,
                "expected_evidence": [
                    {
                        "table": "network_traffic",
                        "where": f"src_ip = '{address}' OR dest_ip = '{address}'",
                        "signature": address,
                    }
                ],
            }
        )
    return cases


def detector_alerts(target: str, flows: list[dict]) -> list[dict]:
    """Emit the alerts a flow detector would raise for this target.

    This is the SOC context the public datasets lack: CIC-IDS2017, UNSW-NB15
    and NF-BoT-IoT ship flows, not alerts. The detector reads only flow shape
    (counts, ports, payload sizes) and never the dataset's label column, so the
    agent still has to judge whether a fired alert is a real incident.
    """
    as_source = [flow for flow in flows if flow["src"] == target]
    as_dest = [flow for flow in flows if flow["dst"] == target]
    alerts: list[dict] = []

    ports = {flow["dport"] for flow in as_source if flow["dport"] is not None}
    if len(as_source) >= 100 and len(ports) >= 25:
        alerts.append(
            {
                "sig_id": "FLOW-001",
                "message": (
                    f"Flow scan: {len(as_source)} outbound flows from {target} "
                    f"across {len(ports)} destination ports"
                ),
                "classification": "Attempted Information Leak",
                "priority": 2,
                "protocol": "tcp",
                "source_ip": target,
                "dest_ip": as_source[0]["dst"] if as_source else "",
                "dest_port": None,
            }
        )

    per_port: dict[tuple, int] = {}
    for flow in as_source:
        key = (flow["dst"], flow["dport"])
        per_port[key] = per_port.get(key, 0) + 1
    if per_port:
        (peer, port), hits = max(per_port.items(), key=lambda item: item[1])
        if hits >= 50:
            alerts.append(
                {
                    "sig_id": "FLOW-002",
                    "message": (
                        f"Repeated connections: {hits} flows from {target} to "
                        f"{peer}:{port} (brute force or service abuse candidate)"
                    ),
                    "classification": "Attempted Administrator Privilege Gain",
                    "priority": 2,
                    "protocol": "tcp",
                    "source_ip": target,
                    "dest_ip": peer,
                    "dest_port": port,
                }
            )

    if len(as_source) >= 100:
        sizes = [flow.get("fwd_bytes") or 0 for flow in as_source]
        average = sum(sizes) / len(sizes)
        if average <= 400:
            alerts.append(
                {
                    "sig_id": "FLOW-003",
                    "message": (
                        f"High-rate small-packet traffic: {len(sizes)} flows from "
                        f"{target} averaging {average:.0f} bytes (flood candidate)"
                    ),
                    "classification": "Attempted Denial of Service",
                    "priority": 2,
                    "protocol": "tcp",
                    "source_ip": target,
                    "dest_ip": as_source[0]["dst"],
                    "dest_port": None,
                }
            )

    sources = {flow["src"] for flow in as_dest if flow["src"] != target}
    if len(as_dest) >= 200 and len(sources) >= 20:
        alerts.append(
            {
                "sig_id": "FLOW-004",
                "message": (
                    f"Inbound flood: {len(as_dest)} flows against {target} from "
                    f"{len(sources)} sources"
                ),
                "classification": "Attempted Denial of Service",
                "priority": 1,
                "protocol": "tcp",
                "source_ip": "",
                "dest_ip": target,
                "dest_port": None,
            }
        )
    elif len(as_dest) >= 50 and 2 <= len(sources) <= 20:
        alerts.append(
            {
                "sig_id": "FLOW-005",
                "message": (
                    f"Beacon receiver: {len(as_dest)} flows from {len(sources)} "
                    f"internal hosts to {target} (C2 candidate)"
                ),
                "classification": "A Network Trojan was detected",
                "priority": 1,
                "protocol": "tcp",
                "source_ip": "",
                "dest_ip": target,
                "dest_port": None,
            }
        )

    return alerts


def write_case_databases(cases: list[dict], cases_root: str) -> dict[str, int]:
    """Write one database per case and return the alert count per case id."""
    alerts_by_case: dict[str, int] = {}
    for case in cases:
        db_path = os.path.join(cases_root, case["id"], "triage.db")
        if os.path.exists(db_path):
            os.remove(db_path)
        conn, cursor = database.init_db(db_path)
        rows = []
        for flow in case["flows"]:
            payload = {
                "duration_us": flow["duration"],
                "fwd_packets": flow["fwd_packets"],
                "bwd_packets": flow["bwd_packets"],
                "fwd_bytes": flow["fwd_bytes"],
                "bwd_bytes": flow["bwd_bytes"],
            }
            uid = f"{case['id']}-{len(rows)}"
            rows.append(
                (
                    uid,
                    flow["ts"],
                    flow["src"],
                    flow["dst"],
                    flow["dport"],
                    flow["proto"],
                    json.dumps(payload),
                )
            )
        cursor.executemany(
            "INSERT OR REPLACE INTO network_traffic "
            "(uid, timestamp, src_ip, dest_ip, dest_port, protocol, session_data) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            rows,
        )

        alerts = detector_alerts(case["target_identifier"], case["flows"])
        alerts_by_case[case["id"]] = len(alerts)
        for alert in alerts:
            cursor.execute(
                "INSERT INTO alerts (timestamp, sensor, src_ip, dest_ip, alert_data) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    None,
                    "FLOW-SENSOR",
                    alert["source_ip"] or None,
                    alert["dest_ip"] or None,
                    json.dumps(alert),
                ),
            )
        conn.commit()
        conn.close()
    return alerts_by_case


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Build CIC-IDS2017 triage cases.")
    parser.add_argument("--src", default=os.path.expanduser("~/data/cicids2017"))
    parser.add_argument("--out", default="eval/datasets/cicids2017.json")
    parser.add_argument("--cases-root", default="data/public/cases")
    parser.add_argument("--holdout", type=float, default=0.5)
    args = parser.parse_args(argv)

    print(f"[cicids] scanning {args.src}")
    targets = scan_source(args.src)
    print(f"[cicids] {len(targets)} addresses seen")

    cases = build_cases(targets, args.holdout)
    print(f"[cicids] sampling flows for {len(cases)} cases ...", flush=True)
    samples = sample_flows(args.src, {case["target_identifier"] for case in cases})
    for case in cases:
        case["flows"] = samples.get(case["target_identifier"], [])
    alert_counts = write_case_databases(cases, args.cases_root)
    # A malicious case must carry evidence an analyst could act on; a benign
    # case is legitimate either way (alert-tripped noise, or a quiet target).
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

    counts = Counter(case["expected_decision"] for case in cases)
    splits = Counter(case["split"] for case in cases)
    print(f"[cicids] {len(cases)} cases -> {args.out}")
    print(f"  decisions: {dict(counts)}")
    print(f"  splits:    {dict(splits)}")
    print(f"  dropped (no detector alert fired): {dropped}")
    print(f"  databases: {args.cases_root}/<case>/triage.db")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())