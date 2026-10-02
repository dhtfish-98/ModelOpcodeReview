"""Synthetic declarations and inert primitive encodings; no unpickling."""

import pickle
import struct
from dataclasses import replace
from hashlib import sha256

import pytest

from model_opcode_review import Limits, review_bytes


def text(value):
    raw = value.encode()
    return b"\x8c" + bytes([len(raw)]) + raw


def codes(report):
    return [entry["code"] for entry in report["findings"]]


@pytest.mark.parametrize("protocol", range(6))
@pytest.mark.parametrize(
    "value",
    [
        None,
        False,
        True,
        123,
        -5678,
        2**70,
        0.25,
        "private-data",
        b"bytes",
        [1, 2],
        (1, None),
        {"a": [1, 2], "b": (False, None)},
    ],
)
def test_primitive_serializations(protocol, value):
    # Older byte pickles call codecs.encode, so their selected analysis is OPEN.
    report = review_bytes(pickle.dumps(value, protocol=protocol))
    assert report["status"] == ("OPEN" if type(value) is bytes and protocol < 3 else "PASS")
    assert all(status == "OPEN" for status in report["external"].values())
    assert "private-data" not in str(report)


@pytest.mark.parametrize("protocol", (4, 5))
@pytest.mark.parametrize("value", [{1, 2}, frozenset({1, 2}), bytearray(b"abc")])
def test_new_primitive_kinds(protocol, value):
    report = review_bytes(pickle.dumps(value, protocol=protocol))
    assert report["status"] == (
        "OPEN" if isinstance(value, bytearray) and protocol == 4 else "PASS"
    )


def test_cycle_and_shared_identity():
    value = []
    value.append(value)
    assert review_bytes(pickle.dumps(value, protocol=4))["status"] == "PASS"
    shared = []
    report = review_bytes(pickle.dumps([shared, shared], protocol=4))
    assert report["counts"]["references"] == 2
    assert report["status"] == "PASS"


@pytest.mark.parametrize(
    "payload", [b"cos\nsystem\n.", b"\x80\x04" + text("os") + text("system") + b"\x93."]
)
def test_risk_global_reference_declaration(payload):
    report = review_bytes(payload)
    assert report["status"] == "FAIL"
    assert "risk_global_reference" in codes(report)
    assert "system" not in str(report)
    assert "reference_sha256" in report["findings"][0]


@pytest.mark.parametrize(
    "module,name",
    [
        ("private.project", "PrivateObject"),
        ("collections", "OrderedDict"),
        ("numpy", "dtype"),
        ("os_private", "system"),
        ("builtins", "eva"),
    ],
)
def test_unknown_and_model_globals_never_safe(module, name):
    report = review_bytes(b"\x80\x04" + text(module) + text(name) + b"\x93.")
    assert report["status"] == "OPEN"
    assert "unresolved_global_reference" in codes(report)
    assert name not in str(report)


@pytest.mark.parametrize(
    "intermediate", [text("junk") + b"0", text("junk") + b"200", b"(K\x01K\x020"]
)
def test_pop_dup_and_mark_do_not_use_nearest_strings(intermediate):
    # Actual top is module 'os', irrespective of discarded recent operands.
    report = review_bytes(b"\x80\x04" + text("os") + intermediate + text("system") + b"\x93.")
    if intermediate.startswith(b"("):
        assert report["status"] == "OPEN"  # dangling MARK makes the target unknown/invalid
    else:
        assert report["status"] == "FAIL"
        assert "unknown_stack_global" not in codes(report)


@pytest.mark.parametrize(
    "put,get",
    [
        (b"p0\n", b"g0\n"),
        (b"q\x00", b"h\x00"),
        (b"r\x00\0\0\0", b"j\x00\0\0\0"),
        (b"\x94", b"h\x00"),
    ],
)
def test_actual_memo_top_value(put, get):
    payload = (
        b"\x80\x04"
        + text("os")
        + b"2"
        + put
        + b"00"
        + text("decoy")
        + b"0"
        + get
        + text("system")
        + b"\x93."
    )
    report = review_bytes(payload)
    assert report["status"] == "FAIL"
    assert "risk_global_reference" in codes(report)


def test_sparse_memoize_uses_len_not_max_index():
    payload = (
        b"\x80\x04"
        + text("decoy")
        + b"q\x0a0"
        + text("os")
        + b"\x940h\x01"
        + text("system")
        + b"\x93."
    )
    assert review_bytes(payload)["status"] == "FAIL"


def test_memo_replacement_and_no_string_cast():
    payload = b"\x80\x04" + text("os") + b"q\x000K\x2aq\x000h\x00" + text("system") + b"\x93."
    report = review_bytes(payload)
    assert report["status"] == "OPEN"
    assert "unknown_stack_global" in codes(report)
    assert "risk_global_reference" not in codes(report)


@pytest.mark.parametrize(
    "payload",
    [
        b"h\x00.",
        b"p-1\n.",
        b"j\xff\xff\xff\xff.",
        b"Nq\x000h\x00h\x00\x93.",
        b"\x80\x04]q\x000h\x00" + text("system") + b"\x93.",
    ],
)
def test_unknown_or_invalid_memo_is_open(payload):
    assert review_bytes(payload)["status"] == "OPEN"


@pytest.mark.parametrize(
    "payload",
    [
        b".",
        b"0N.",
        b"1N.",
        b"2.",
        b"(N.",
        b"NN.",
        b"(K\x01d.",
        b"]K\x01s.",
        b"](K\x01u.",
        b"(o.",
        b"K\x01a.",
        b"K\x01K\x02R.",
        b"\x80\x06N.",
        b"N\x80\x04.",
        b"\x80\x00N.",
        b"\x80\x01N.",
        b"\x88.",
    ],
)
def test_stack_and_protocol_errors_are_open(payload):
    assert review_bytes(payload)["status"] == "OPEN"


@pytest.mark.parametrize(
    "payload",
    [
        b"]K\x01a.",
        b"](K\x01K\x02e.",
        b"}(K\x01K\x02u.",
        b"}K\x01K\x02s.",
        b"(K\x01K\x02l.",
        b"(K\x01K\x02t.",
        b"(K\x01K\x02d.",
        b"\x80\x04\x8f(K\x01\x90.",
        b"\x80\x04(K\x01\x91.",
        b"\x80\x02K\x01\x85.",
        b"\x80\x02K\x01K\x02\x86.",
        b"\x80\x02K\x01K\x02K\x03\x87.",
        b"(K\x011N.",
        b"(0N.",
    ],
)
def test_container_stack_semantics(payload):
    assert review_bytes(payload)["status"] == "PASS"


@pytest.mark.parametrize(
    "payload", [b"}]K\x01s.", b"\x80\x04\x8f(]\x90.", b"\x80\x04(]\x91.", b"}(]K\x01u."]
)
def test_unhashable_static_keys_are_not_complete(payload):
    report = review_bytes(payload)
    assert report["status"] == "OPEN"
    assert "unhashable_container_key" in codes(report)


@pytest.mark.parametrize(
    "payload,code",
    [
        (b"cprivate\nThing\n)R.", "reduce_potential_call"),
        (b"\x80\x02cprivate\nThing\n)\x81.", "object_construction"),
        (b"\x80\x04cprivate\nThing\n)}\x92.", "object_construction"),
        (b"(cprivate\nThing\nK\x01o.", "object_construction"),
        (b"(K\x01iprivate\nThing\n.", "instance_construction"),
        (b"cprivate\nThing\n)RNb.", "build_potential_state_hook"),
    ],
)
def test_object_reference_events(payload, code):
    report = review_bytes(payload)
    assert report["status"] == "OPEN"
    assert code in codes(report)


@pytest.mark.parametrize(
    "payload",
    [
        b"\x80\x02\x82\x01.",
        b"\x80\x02\x83\x01\0.",
        b"\x80\x02\x84\x01\0\0\0.",
        b"Pprivate-id\n.",
        b"NQ.",
        b"\x80\x05\x97.",
        b"\x80\x05\x97\x98.",
    ],
)
def test_external_references_are_open(payload):
    report = review_bytes(payload)
    assert report["status"] == "OPEN"
    assert "private-id" not in str(report)


@pytest.mark.parametrize("body", [b"N.", b"](K\x01K\x02e."])
def test_frame_exact_span(body):
    payload = b"\x80\x04\x95" + struct.pack("<Q", len(body)) + body
    assert review_bytes(payload)["status"] == "PASS"


@pytest.mark.parametrize(
    "payload",
    [
        b"\x80\x04\x95" + struct.pack("<Q", 1) + b"K\x01.",
        b"\x80\x04\x95" + struct.pack("<Q", 3) + b"N.N",
        b"\x80\x04\x95" + struct.pack("<Q", 3) + b"N.",
        b"\x80\x04\x95" + struct.pack("<Q", 100000) + b"N.",
        b"\x80\x04\x95" + struct.pack("<Q", 0) + b"N.",
        b"\x80\x03\x95" + struct.pack("<Q", 2) + b"N.",
        b"\x80\x04\x95" + struct.pack("<Q", 11) + b"\x95" + struct.pack("<Q", 2) + b"N.",
    ],
)
def test_frame_truncation_crossing_and_nested(payload):
    assert review_bytes(payload)["status"] == "OPEN"


def test_adjacent_frames_and_unframed_tail():
    def frame(body):
        return b"\x95" + struct.pack("<Q", len(body)) + body

    assert review_bytes(b"\x80\x04" + frame(b"N") + frame(b"."))["status"] == "PASS"
    assert review_bytes(b"\x80\x04" + frame(b"N") + b".")["status"] == "PASS"


def test_multiple_streams_and_evidence_before_truncation():
    report = review_bytes(b"N.cos\nsystem\n.")
    assert report["status"] == "FAIL"
    assert report["analysis_completeness"] == "INCOMPLETE"
    assert report["counts"]["streams"] == 2
    report = review_bytes(b"cos\nsystem\n")
    assert report["status"] == "FAIL"
    assert "invalid_or_truncated_opcode" in codes(report)
    assert review_bytes(b"N.N.")["status"] == "OPEN"
    assert review_bytes(b"Np0\n.g0\n.")["status"] == "OPEN"


@pytest.mark.parametrize(
    "payload", [b"", b"not pickle", b"\xff", b"\x80", b"\x80\x04\x8c\x04x", b"c\xff\nname\n."]
)
def test_invalid_input_never_clean(payload):
    assert review_bytes(payload)["status"] == "OPEN"


def test_privacy_and_hash():
    payload = text("private-token-123") + b"."
    report = review_bytes(payload)
    assert report["input_sha256"] == sha256(payload).hexdigest()
    assert "private-token-123" not in str(report)
    assert report == review_bytes(payload)


@pytest.mark.parametrize(
    "field,payload,value",
    [
        ("input_bytes", b"N.", 1),
        ("opcodes", b"N.", 1),
        ("nodes", b"NN\x86.", 1),
        ("stack", b"NN\x86.", 1),
        ("memo", b"Nq\x01.", 1),
        ("references", b"NN\x86.", 1),
        ("streams", b"N.N.", 1),
        ("operand_bytes", text("longstring") + b".", 1),
        ("findings", b"NQNb.", 1),
    ],
)
def test_budgets(field, payload, value):
    report = review_bytes(payload, limits=replace(Limits(), **{field: value}))
    assert report["status"] == "OPEN"
    assert report["analysis_completeness"] == "INCOMPLETE"


@pytest.mark.parametrize("value", [None, bytearray(b"N."), "N.", 1])
def test_library_bytes_contract(value):
    with pytest.raises(ValueError):
        review_bytes(value)


@pytest.mark.parametrize(
    "field,value",
    [("opcodes", True), ("members", 0), ("input_bytes", 16777217), ("report_bytes", 1)],
)
def test_limits_contract(field, value):
    with pytest.raises(ValueError):
        review_bytes(b"N.", limits=replace(Limits(), **{field: value}))
