"""Deterministic rule-based triage baseline.

No model, no network, no randomness: the same database and target always
produce the same verdict. This exists so the eval can say what the LLM adds
over a cheap, explainable baseline instead of quoting an accuracy number with
nothing to compare it to.

The rules are deliberately coarse. They read the evidence tables with fixed
SQL and score string/pattern evidence; they do not try to encode an analyst's
judgement.
"""
from __future__ import annotations

import ipaddress
import json
import os
from dataclasses import dataclass, field

import database
from config import settings

# Alert text that indicates the activity itself is hostile.
MALICIOUS_ALERT_KEYWORDS = (
    "scan",
    "nikto",
    "sql injection",
    "sqli",
    "exploit",
    "shell",
    "webshell",
    "malware",
    "trojan",
    "backdoor",
    "c2",
    "command and control",
    "brute force",
    "credential",
    "botnet",
    "spam",
    "executable code",
    "attempted-recon",
    "web-application-attack",
    "policy-violation",
)

# Endpoint command/event text that only shows up after an attacker lands.
HOST_SIGNAL_POINTS = {
    "/dev/tcp/": 40,
    "bash -i": 40,
    "nc -e": 40,
    "ncat -e": 40,
    "-w hidden -enc": 40,
    "mimikatz": 40,
    "sekurlsa": 35,
    "procdump": 35,
    "lsass.dmp": 30,
    "powershell -enc": 30,
    "encodedcommand": 30,
    "downloadstring": 25,
    "invoke-webrequest": 20,
    "useradd": 30,
    "net localgroup administrators": 30,
    "event_id\": 4720": 30,
    "event_id\": 4732": 25,
    "event_id\": 4698": 25,
    "vssadmin delete shadows": 30,
    "ntdsutil": 30,
    "tar -czf": 20,
    "rclone": 30,
    "nmap": 20,
    "masscan": 25,
    "wevtutil cl": 20,
    "crontab -": 15,
    "chmod +x": 10,
    "whoami /priv": 20,
    " /add": 10,
    "relay accepted": 25,
    "xp_cmdshell": 30,
}

# Text that shows the target is noise rather than an incident.
BENIGN_ALERT_KEYWORDS = (
    "informational",
    "not suspicious",
    "known-good",
    "policy",
    "cve-2019-",
)

BRUTE_FORCE_MIN_FAILURES = 5
BEACON_MIN_SESSIONS = 6
ISOLATE_THRESHOLD = 40


@dataclass
class RuleVerdict:
    decision: str
    confidence_score: int
    reasoning: str
    score: int = 0
    evidence: list[str] = field(default_factory=list)


def _db_path(db_path: str | None) -> str:
    return db_path or settings.triage_db_path


def _rows(sql: str, params=(), db_path: str | None = None) -> list[dict]:
    try:
        return database.query(sql, params, db_path=_db_path(db_path))
    except FileNotFoundError:
        return []


def _is_external(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not address.is_private and not address.is_loopback


def _text_of(rows: list[dict]) -> str:
    """Flatten rows to searchable text, decoding the JSON payload columns once.

    The payload columns are stored as JSON text; dumping the row without
    decoding them double-escapes every quote and defeats pattern matching.
    """
    decoded: list[dict] = []
    for row in rows:
        item = dict(row)
        for key in ("event_data", "session_data", "alert_data"):
            value = item.get(key)
            if isinstance(value, str):
                try:
                    item[key] = json.loads(value)
                except json.JSONDecodeError:
                    pass
        decoded.append(item)
    return json.dumps(decoded, default=str).lower()


def _alert_rows_for_ip(target: str, db_path: str | None) -> list[dict]:
    return _rows(
        "SELECT * FROM alerts WHERE src_ip = ? OR dest_ip = ?",
        (target, target),
        db_path,
    )


def _sessions_from_ip(target: str, db_path: str | None) -> list[dict]:
    return _rows(
        "SELECT * FROM network_traffic WHERE src_ip = ?",
        (target,),
        db_path,
    )


def _sessions_to_ip(target: str, db_path: str | None) -> list[dict]:
    return _rows(
        "SELECT * FROM network_traffic WHERE dest_ip = ?",
        (target,),
        db_path,
    )


def _beacon_like(sessions: list[dict]) -> bool:
    """Rough periodic-beacon test: many sessions, one peer, steady byte sizes."""
    if len(sessions) < BEACON_MIN_SESSIONS:
        return False
    peers = {row.get("dest_ip") or row.get("src_ip") for row in sessions}
    if len(peers) > 2:
        return False
    sizes = []
    for row in sessions:
        payload = row.get("session_data")
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError:
                payload = {}
        connection = (payload or {}).get("connection") or {}
        sizes.append(
            int(
                connection.get("bytes_sent")
                or connection.get("orig_bytes")
                or 0
            )
        )
    if not sizes:
        return False
    average = sum(sizes) / len(sizes)
    if average <= 0:
        return False
    # A human session varies a lot; a beacon keeps a tight packet size.
    return max(sizes) <= average * 2.0


def classify_ip(target: str, db_path: str | None = None) -> RuleVerdict:
    alerts = _alert_rows_for_ip(target, db_path)
    inbound = _sessions_to_ip(target, db_path)
    outbound = _sessions_from_ip(target, db_path)

    if not _is_external(target):
        return RuleVerdict(
            decision="IGNORE",
            confidence_score=45,
            reasoning=f"{target} is an internal address; no external threat to block.",
            score=0,
        )

    alert_text = _text_of(alerts).lower()
    malicious_hits = [kw for kw in MALICIOUS_ALERT_KEYWORDS if kw in alert_text]
    evidence: list[str] = []

    if malicious_hits:
        confidence = min(95, 55 + 8 * len(alerts))
        evidence.append(
            f"{len(alerts)} alert(s) matching {', '.join(malicious_hits[:3])}"
        )
        return RuleVerdict(
            decision="BLOCK_IP",
            confidence_score=confidence,
            reasoning=(
                f"External {target} raised {len(alerts)} IDS alert(s) whose text "
                f"matches malicious indicators ({', '.join(malicious_hits[:3])})."
            ),
            score=60,
            evidence=evidence,
        )

    if _beacon_like(inbound):
        return RuleVerdict(
            decision="BLOCK_IP",
            confidence_score=70,
            reasoning=(
                f"External {target} received {len(inbound)} outbound sessions of "
                "near-constant size, consistent with a beacon."
            ),
            score=45,
            evidence=[f"{len(inbound)} regular sessions to {target}"],
        )

    if inbound and _beacon_like(outbound):
        return RuleVerdict(
            decision="BLOCK_IP",
            confidence_score=60,
            reasoning=(
                f"External {target} is one end of {len(outbound)} regular "
                "sessions; treating it as C2 infrastructure."
            ),
            score=40,
            evidence=[f"{len(outbound)} regular sessions from {target}"],
        )

    benign = [kw for kw in BENIGN_ALERT_KEYWORDS if kw in alert_text]
    if benign:
        return RuleVerdict(
            decision="IGNORE",
            confidence_score=55,
            reasoning=(
                f"Alerts for {target} are tagged informational/policy rather than "
                "hostile."
            ),
            score=0,
            evidence=[f"benign alert text: {', '.join(benign[:3])}"],
        )

    return RuleVerdict(
        decision="IGNORE",
        confidence_score=40,
        reasoning=(
            f"No malicious signature, beacon pattern or exploit evidence for {target}."
        ),
        score=0,
    )


def _host_events(target: str, db_path: str | None) -> list[dict]:
    return _rows(
        "SELECT * FROM endpoint_events WHERE hostname = ?",
        (target,),
        db_path,
    )


def _host_ip_candidates(events: list[dict], target: str) -> list[str]:
    """Pull internal addresses out of a host's own telemetry."""
    found: set[str] = set()
    for row in events:
        blob = row.get("event_data") or ""
        if isinstance(blob, str):
            for token in blob.replace('"', " ").replace(",", " ").split():
                token = token.strip("{}[]():'")
                try:
                    address = ipaddress.ip_address(token)
                except ValueError:
                    continue
                if address.is_private or not address.is_loopback:
                    found.add(str(address))
    return sorted(found)


def classify_host(target: str, db_path: str | None = None) -> RuleVerdict:
    events = _host_events(target, db_path)
    if not events:
        return RuleVerdict(
            decision="IGNORE",
            confidence_score=30,
            reasoning=f"No telemetry found for host {target}.",
            score=0,
        )

    text = _text_of(events).lower()
    score = 0
    evidence: list[str] = []

    failures = text.count("failed password")
    successes = text.count("accepted password")
    if failures >= BRUTE_FORCE_MIN_FAILURES and successes:
        score += 35
        evidence.append(f"{failures} failed SSH passwords followed by a success")
    elif failures >= BRUTE_FORCE_MIN_FAILURES:
        score += 15
        evidence.append(f"{failures} failed SSH passwords")

    windows_failures = text.count('"event_id": 4625')
    if windows_failures >= BRUTE_FORCE_MIN_FAILURES:
        score += 20
        evidence.append(f"{windows_failures} failed Windows logons")

    if text.count("relay accepted") >= 20:
        score += 25
        evidence.append("bulk outbound SMTP relay")

    # An external address inside the host's own telemetry is context, not proof.
    for candidate in _host_ip_candidates(events, target):
        if _is_external(candidate):
            score += 5
            evidence.append(f"external peer {candidate}")
            break

    for marker, points in HOST_SIGNAL_POINTS.items():
        if marker in text:
            score += points
            evidence.append(f"marker: {marker}")

    # Outbound beacons belonging to this host's addresses.
    for candidate in _host_ip_candidates(events, target):
        sessions = _sessions_from_ip(candidate, db_path)
        if sessions and _beacon_like(sessions):
            score += 30
            evidence.append(f"beacon-shaped traffic from {candidate}")
            break

    if score >= ISOLATE_THRESHOLD:
        return RuleVerdict(
            decision="ISOLATE_HOST",
            confidence_score=min(95, 50 + score // 2),
            reasoning=(
                f"{target} shows post-compromise activity: "
                + "; ".join(evidence[:4])
            ),
            score=score,
            evidence=evidence,
        )

    return RuleVerdict(
        decision="IGNORE",
        confidence_score=60,
        reasoning=(
            f"{target} telemetry shows routine activity; strongest signals: "
            + ("; ".join(evidence[:3]) if evidence else "none")
        ),
        score=score,
        evidence=evidence,
    )


def classify(target: str, db_path: str | None = None) -> RuleVerdict:
    """Classify a hostname or an IP address."""
    try:
        ipaddress.ip_address(target)
    except ValueError:
        return classify_host(target, db_path)
    return classify_ip(target, db_path)