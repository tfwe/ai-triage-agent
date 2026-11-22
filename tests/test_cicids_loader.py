"""CIC-IDS2017 labelling policy: decisions are derived from labels, not hand-set."""
from __future__ import annotations

from eval.load_cicids import Target, build_cases, classify_target


def target(src_labels=None, dst_labels=None, count=100):
    item = Target()
    for label, hits in (src_labels or {}).items():
        item.as_src[label] = hits
    for label, hits in (dst_labels or {}).items():
        item.as_dst[label] = hits
    item.count = count
    return item


def test_external_attacker_is_blocked():
    decision, reason = classify_target("205.174.165.73", target({"PortScan": 50}))

    assert decision == "BLOCK_IP"
    assert "PortScan".lower() in reason.lower()


def test_internal_bot_is_isolated():
    decision, reason = classify_target("172.16.0.5", target({"Botnet": 40, "BENIGN": 10}))

    assert decision == "ISOLATE_HOST"
    assert "BOTNET" in reason.upper()


def test_internal_attacker_is_isolated_not_blocked():
    from eval.load_botiot import classify_target as botiot_classify

    decision, reason = botiot_classify("192.168.100.147", target({"ATTACK": 90}))

    assert decision == "ISOLATE_HOST"
    assert "compromised" in reason


def test_external_c2_is_blocked():
    decision, reason = classify_target(
        "205.174.165.73", target({"BENIGN": 5}, {"Botnet": 60})
    )

    assert decision == "BLOCK_IP"
    assert "C2" in reason


def test_benign_only_address_is_ignored():
    decision, _ = classify_target("8.8.8.8", target({"BENIGN": 500}))

    assert decision == "IGNORE"


def test_mixed_labels_are_dropped_as_ambiguous():
    decision, reason = classify_target("172.16.0.9", target({"BENIGN": 5}, {"DoS Hulk": 3}))

    assert decision is None
    assert "ambiguous" in reason.lower()


def test_internal_host_that_only_suffered_traffic_is_not_isolated():
    """A victim of a flood is not a compromised host."""
    decision, _ = classify_target("172.16.0.7", target({"BENIGN": 10}, {"DDoS": 400}))

    assert decision is None


def test_split_is_deterministic():
    targets = {
        f"10.0.0.{i}": target({"BENIGN": 100}) for i in range(1, 40)
    }
    targets["205.174.165.73"] = target({"PortScan": 90})

    first = {case["id"]: case["split"] for case in build_cases(targets)}
    second = {case["id"]: case["split"] for case in build_cases(targets)}

    assert first == second
    assert set(first.values()) <= {"dev", "holdout"}


def test_thin_targets_are_skipped():
    targets = {"205.174.165.73": target({"PortScan": 3}, count=3)}

    assert build_cases(targets) == []