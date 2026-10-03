"""Decoder warning boundaries using inert protocol0 byte strings only."""

import json
import subprocess
import sys
import warnings

import pytest

from model_opcode_review import review_bytes

CASES = (
    (b"N.", "PASS", 0, False),
    (b"S'private\\q'\n.", "OPEN", 2, True),
    (b"(S'private\\q'\ncos\nsystem\nt.", "FAIL", 1, True),
    (b"S'private\\q'\n?", "OPEN", 2, True),
)


@pytest.mark.parametrize("caller_filter", ("always", "default", "ignore", "error"))
@pytest.mark.parametrize("data,status,code,has_warning", CASES)
def test_pickle_warning_api_contract(caller_filter, data, status, code, has_warning):
    with warnings.catch_warnings(record=True) as observed:
        warnings.simplefilter(caller_filter)
        report = review_bytes(data, format="pickle")
    assert not observed
    assert report["status"] == status
    codes = [item["code"] for item in report["findings"]]
    assert ("pickle_decode_warning" in codes) is has_warning
    if has_warning:
        assert report["analysis_completeness"] == "INCOMPLETE"
    if status == "FAIL":
        assert "risk_global_reference" in codes
    assert "private" not in json.dumps(report)


@pytest.mark.parametrize("caller_filter", ("always", "default", "ignore", "error"))
@pytest.mark.parametrize("data,status,code,has_warning", CASES)
def test_pickle_warning_cli_contract(tmp_path, caller_filter, data, status, code, has_warning):
    path = tmp_path.resolve() / "PRIVATE_WARNING.pkl"
    path.write_bytes(data)
    before = path.stat().st_mtime_ns
    result = subprocess.run(
        [sys.executable, "-W" + caller_filter, "-m", "model_opcode_review", str(path)],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == code and not result.stderr
    report = json.loads(result.stdout)
    assert report["status"] == status
    assert ("pickle_decode_warning" in [item["code"] for item in report["findings"]]) is has_warning
    assert "private" not in result.stdout and "PRIVATE_WARNING" not in result.stdout
    assert path.read_bytes() == data and path.stat().st_mtime_ns == before
