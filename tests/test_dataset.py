"""The golden dataset and its evidence corpus must stay in lockstep."""
from __future__ import annotations

import json
import os

import pytest

import database
from eval.corpus_build import CASES_ROOT, build as build_corpus
from eval.run_evals import case_db, dataset_digest, load_dataset

VALID_DECISIONS = {"BLOCK_IP", "ISOLATE_HOST", "IGNORE"}
REQUIRED = {"id", "target_identifier", "expected_decision", "description", "expected_evidence"}


@pytest.fixture(scope="module")
def corpus():
    missing = [
        case["id"] for case in load_dataset() if not os.path.exists(case_db(case["id"]))
    ]
    if missing:
        build_corpus()
    return load_dataset()


def test_dataset_has_the_required_shape(corpus):
    assert len(corpus) >= 30
    for case in corpus:
        assert REQUIRED <= set(case), case["id"]
        assert case["expected_decision"] in VALID_DECISIONS
        assert case["target_identifier"]
        assert case["description"]
        assert dataset_digest()


def test_every_case_carries_expected_evidence(corpus):
    with_evidence = [case for case in corpus if case["expected_evidence"]]
    assert len(with_evidence) >= len(corpus) - 1
    for case in with_evidence:
        for item in case["expected_evidence"]:
            assert set(item) == {"table", "where", "signature"}
            assert item["table"] in database.SCHEMA
            assert item["signature"], case["id"]


def test_benign_cases_make_the_false_positive_rate_measurable(corpus):
    benign = [case for case in corpus if case["expected_decision"] == "IGNORE"]
    assert len(benign) >= 10
    assert len(benign) < len(corpus)


def test_case_ids_match_the_scenario_corpus(corpus):
    with open("eval/corpus/scenarios.json", encoding="utf-8") as handle:
        scenarios = json.load(handle)
    assert {case["id"] for case in corpus} == {scenario["id"] for scenario in scenarios}


def test_scenarios_target_matches_dataset_target(corpus):
    with open("eval/corpus/scenarios.json", encoding="utf-8") as handle:
        scenarios = {scenario["id"]: scenario["target"] for scenario in json.load(handle)}
    for case in corpus:
        assert scenarios[case["id"]] == case["target_identifier"]


def test_every_expected_evidence_row_exists_in_its_case_database(corpus):
    """The corpus must actually contain the evidence the label depends on."""
    missing = []
    for case in corpus:
        db_path = case_db(case["id"], CASES_ROOT)
        for item in case["expected_evidence"]:
            rows = database.query(
                f"SELECT 1 FROM {item['table']} WHERE {item['where']}", db_path=db_path
            )
            if not rows:
                missing.append((case["id"], item["table"], item["where"]))
    assert missing == []


def test_case_databases_are_isolated(corpus):
    """A case must not inherit another case's telemetry."""
    case = next(c for c in corpus if c["id"] == "CASE-028-BENIGN-NO-EVIDENCE")
    db_path = case_db(case["id"], CASES_ROOT)
    for table in database.SCHEMA:
        assert database.query(f"SELECT count(*) AS c FROM {table}", db_path=db_path)[0]["c"] == 0