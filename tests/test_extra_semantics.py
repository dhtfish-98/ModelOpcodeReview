import json
import random
import struct
from dataclasses import replace

import pytest

from model_opcode_review import Limits, review_bytes


@pytest.mark.parametrize(
    "payload",
    [
        b"\x80\x04\x8d" + struct.pack("<Q", 2) + b"os" + b"\x8c\x06system\x93.",
        b"\x80\x04X\x02\0\0\0os\x8c\x06system\x93.",
        b"Vos\nVsystem\n\x93.",
        b"S'os'\nS'system'\n\x93.",
        b"T\x02\0\0\0osU\x06system\x93.",
    ],
)
def test_all_string_operand_forms(payload):
    assert review_bytes(payload)["status"] == "FAIL"


@pytest.mark.parametrize(
    "payload",
    [
        b"\x80\x04C\x02os\x8c\x06system\x93.",
        b"\x80\x04U\x01\xff\x8c\x06system\x93.",
        b"\x80\x04\x8c\x03o\0s\x8c\x06system\x93.",
    ],
)
def test_bytes_legacy_and_nul_not_string_guessed(payload):
    assert review_bytes(payload)["status"] == "OPEN"


def test_aliased_memo_global_invocation_identity():
    # Declaration and symbolic empty-argument constructor; never execute it.
    report = review_bytes(b"cprivate\nThing\np0\n0g0\n)R.")
    events = report["findings"]
    reference = next(
        event["reference_sha256"]
        for event in events
        if event["code"] == "unresolved_global_reference"
    )
    call = next(event for event in events if event["code"] == "reduce_potential_call")
    assert call["reference_sha256"] == reference and call["target_identity"] == 1


def test_symbolic_mutation_of_constructed_object_open():
    report = review_bytes(b"cprivate\nThing\n)RK\x01a.")
    assert "dynamic_container_method" in [event["code"] for event in report["findings"]]


def test_graph_key_work_budget():
    payload = b"\x80\x02}K\x01\x85K\x02s."
    assert review_bytes(payload)["status"] == "PASS"
    assert review_bytes(payload, limits=replace(Limits(), work=1))["status"] == "OPEN"


def test_report_budget_retains_failure_and_completeness():
    payload = b"(" + b"cos\nsystem\n" * 20 + b"l."
    report = review_bytes(payload, limits=replace(Limits(), report_bytes=2048))
    assert report["status"] == "FAIL" and report["analysis_completeness"] == "INCOMPLETE"
    assert report["findings"] == [{"code": "budget_report", "status": "OPEN"}]
    assert len(json.dumps(report).encode()) <= 2048


def test_oversized_input_is_not_hashed(monkeypatch):
    import model_opcode_review.contracts as contracts

    def forbidden(data):
        raise AssertionError("input beyond byte budget was hashed")

    monkeypatch.setattr(contracts, "sha256", forbidden)
    report = review_bytes(b"N.", limits=replace(Limits(), input_bytes=1))
    assert report["status"] == "OPEN" and report["input_sha256"] is None


def test_fixed_seed_malformed_smoke_total_api():
    # Fixed parser smoke only; this value never generates keys or secrets.
    randomizer = random.Random(22129)  # noqa: S311
    for _ in range(500):
        data = randomizer.randbytes(randomizer.randrange(1, 65))
        report = review_bytes(data)
        assert report["status"] in {"PASS", "FAIL", "OPEN"}
        assert len(json.dumps(report).encode()) < 262144


@pytest.mark.parametrize("requested", ("npy", "zip", "private-format", None, []))
def test_explicit_format_cannot_claim_other_data(requested):
    report = review_bytes(b"N.", format=requested)
    assert report["status"] == "OPEN"
    assert "private-format" not in json.dumps(report)
