import json
import os
import subprocess
import sys
import time
from dataclasses import replace
from types import SimpleNamespace

import pytest

from model_opcode_review import Limits, review_bytes, review_file
from model_opcode_review.cli import main


def test_readonly_hash_privacy(tmp_path):
    path = tmp_path.resolve() / "PRIVATE_SOURCE.pkl"
    path.write_bytes(b"N.")
    before = path.stat()
    report = review_file(path)
    assert report["status"] == "PASS"
    assert path.read_bytes() == b"N."
    assert path.stat().st_mtime_ns == before.st_mtime_ns
    assert "PRIVATE_SOURCE" not in json.dumps(report)


@pytest.mark.parametrize(
    "kind",
    [
        "missing",
        "directory",
        "leaf_link",
        "parent_link",
        "parent",
        "nul",
        "empty",
        "fifo",
        "device",
        "url",
    ],
)
def test_input_errors_private_nonblocking(tmp_path, kind):
    directory = tmp_path.resolve()
    source = directory / "PRIVATE.pkl"
    source.write_bytes(b"N.")
    path = directory / "PRIVATE_MISSING"
    if kind == "directory":
        path = directory
    elif kind == "leaf_link":
        path = directory / "link"
        path.symlink_to(source)
    elif kind == "parent_link":
        alias = directory / "alias"
        alias.symlink_to(directory, target_is_directory=True)
        path = alias / source.name
    elif kind == "parent":
        path = str(directory / "x/../PRIVATE.pkl")
    elif kind == "nul":
        path = "PRIVATE\0TOKEN"
    elif kind == "empty":
        path = ""
    elif kind == "fifo":
        path = directory / "fifo"
        os.mkfifo(path)
    elif kind == "device":
        path = "/dev/null"
    elif kind == "url":
        path = "https://PRIVATE.invalid/model.pkl"
    start = time.monotonic()
    report = review_file(path)
    assert report["status"] == "OPEN"
    assert report["input_sha256"] is None
    assert time.monotonic() - start < 1
    assert "PRIVATE" not in json.dumps(report)


@pytest.mark.parametrize("field", ["st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"])
def test_reader_metadata_changes(tmp_path, monkeypatch, field):
    path = tmp_path.resolve() / "data.pkl"
    path.write_bytes(b"N.")
    original, calls = os.fstat, 0

    def fstat(fd):
        nonlocal calls
        calls += 1
        item = original(fd)
        values = {
            key: getattr(item, key)
            for key in ("st_mode", "st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        }
        if calls == 2:
            values[field] += 1
        return SimpleNamespace(**values)

    monkeypatch.setattr(os, "fstat", fstat)
    assert review_file(path)["status"] == "OPEN"


def test_reader_capabilities_short_read_and_limit(tmp_path, monkeypatch):
    path = tmp_path.resolve() / "data.pkl"
    path.write_bytes(b"N.")
    assert review_file(path, limits=replace(Limits(), input_bytes=1))["status"] == "OPEN"
    with monkeypatch.context() as patch:
        patch.setattr(os, "read", lambda *args: b"")
        assert review_file(path)["status"] == "OPEN"
    with monkeypatch.context() as patch:
        patch.setattr(os, "supports_dir_fd", set())
        assert review_file(path)["status"] == "OPEN"
    monkeypatch.delattr(os, "O_NOFOLLOW")
    assert review_file(path)["status"] == "OPEN"


@pytest.mark.parametrize(
    "arguments",
    [[], ["PRIVATE", "--execute"], ["PRIVATE", "--format", "exe"], ["PRIVATE", "OTHER"]],
)
def test_cli_argument_errors(arguments, capsys):
    assert main(arguments) == 2
    output = capsys.readouterr()
    assert json.loads(output.out)["status"] == "OPEN"
    assert "PRIVATE" not in output.out + output.err


@pytest.mark.parametrize(
    "payload,status,code", [(b"N.", "PASS", 0), (b"cos\nsystem\n.", "FAIL", 1), (b"N", "OPEN", 2)]
)
def test_cli_results(tmp_path, capsys, payload, status, code):
    path = tmp_path.resolve() / "PRIVATE_SOURCE.pkl"
    path.write_bytes(payload)
    assert main([str(path)]) == code
    output = capsys.readouterr()
    assert json.loads(output.out)["status"] == status
    assert "PRIVATE_SOURCE" not in output.out and not output.err


def test_module_cli_and_no_execute(tmp_path):
    path = tmp_path.resolve() / "sample.pkl"
    path.write_bytes(b"N.")
    result = subprocess.run(
        [sys.executable, "-m", "model_opcode_review", str(path)],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0
    assert json.loads(result.stdout)["status"] == "PASS"
    assert not result.stderr


def test_runtime_never_target_import_or_execute(monkeypatch):
    import builtins
    import pickle
    import socket

    def forbidden(*args, **kwargs):
        raise AssertionError("target execution attempted")

    monkeypatch.setattr(pickle, "load", forbidden)
    monkeypatch.setattr(pickle, "loads", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    original = builtins.__import__

    def imports(name, *args, **kwargs):
        if name.startswith(("numpy", "torch", "PRIVATE")):
            forbidden()
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", imports)
    for payload in (b"cPRIVATE\nObject\n.", b"cnumpy\ndtype\n.", b"ctorch\nFloatStorage\n.", b"N."):
        assert review_bytes(payload)["status"] in {"PASS", "OPEN"}
