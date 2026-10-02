import io
import json
import stat
import struct
import zipfile
import zlib
from dataclasses import replace

import pytest

from model_opcode_review import Limits, review_bytes


def npy(descr="<i4", shape=(2,), payload=b"\0" * 8, version=1, order=False, raw_header=None):
    start = 10 if version == 1 else 12
    header = (
        repr({"descr": descr, "fortran_order": order, "shape": shape})
        if raw_header is None
        else raw_header
    )
    raw = header.encode("utf-8" if version == 3 else "latin1")
    raw += b" " * ((-start - len(raw) - 1) % 64) + b"\n"
    return (
        b"\x93NUMPY" + bytes([version, 0]) + len(raw).to_bytes(start - 8, "little") + raw + payload
    )


def archive(entries=(("data.pkl", b"N."),), method=0):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=method) as z:
        for name, data in entries:
            z.writestr(name, data)
    return output.getvalue()


def codes(report):
    return [entry["code"] for entry in report["findings"]]


@pytest.mark.parametrize("version", (1, 2, 3))
@pytest.mark.parametrize(
    "descr,shape,size",
    [
        ("<i4", (2,), 8),
        ("|u1", (3,), 3),
        (">f8", (), 8),
        ("|S4", (2, 2), 16),
        ("<U2", (1,), 8),
        ("|V0", (2,), 0),
        ("|b1", (0,), 0),
        ([("a", "<i2"), ("b", "<f4", (2,))], (1,), 10),
        ([("nested", [("c", "|u1")])], (3,), 3),
    ],
)
def test_numeric_and_structured_npy(version, descr, shape, size):
    report = review_bytes(npy(descr, shape, b"\0" * size, version, True))
    assert report["status"] == "PASS"


@pytest.mark.parametrize(
    "descr", ["|O", "|O8", [("private", "|O", (2,))], [("nested", [("object", "|O")])]]
)
def test_object_npy_static_only(descr):
    report = review_bytes(npy(descr, (1,), b"N."))
    assert report["status"] == "OPEN"
    assert "npy_object_dtype" in codes(report)
    assert report["counts"]["opcodes"] == 2
    assert "private" not in json.dumps(report)


def test_object_npy_preserves_reference_findings():
    report = review_bytes(npy("|O", (1,), b"cos\nsystem\n."))
    assert report["status"] == "FAIL"
    assert "npy_object_dtype" in codes(report)
    assert "risk_global_reference" in codes(report)


@pytest.mark.parametrize(
    "descr",
    [
        "object",
        "<f3",
        "<i3",
        "|O3",
        "<M8[ns]",
        {},
        [],
        [("x", "<i4"), ("x", "<i4")],
        [(("title", "name"), "<i4")],
    ],
)
def test_unknown_dtype_is_open(descr):
    assert review_bytes(npy(descr))["status"] == "OPEN"


@pytest.mark.parametrize(
    "shape", [(True,), (-1,), [2], (33554433,), (33554432, 2), tuple(range(33))]
)
def test_npy_shapes(shape):
    assert review_bytes(npy(shape=shape))["status"] == "OPEN"


@pytest.mark.parametrize(
    "header",
    [
        "{'descr':'<i4','shape':(2,),'fortran_order':False,'extra':1}",
        "{'descr':'<i4','descr':'|O','shape':(2,),'fortran_order':False}",
        "{'descr':some_call(),'shape':(2,),'fortran_order':False}",
        "{'descr':'<i4','shape':(2,),'fortran_order':0}",
        "['private']",
        "{'descr':'<i4','shape':(2,),'fortran_order':False",
    ],
)
def test_header_literal_no_execution(header):
    assert review_bytes(npy(raw_header=header))["status"] == "OPEN"


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d[:6] + b"\x04\0" + d[8:],
        lambda d: d[:-1],
        lambda d: d + b"x",
        lambda d: d[:8] + b"\xff\xff" + d[10:],
        lambda d: d[:127] + b"x" + d[128:],
    ],
)
def test_npy_header_and_payload_truncation(change):
    assert review_bytes(change(npy()))["status"] == "OPEN"


@pytest.mark.parametrize("method", (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED))
@pytest.mark.parametrize(
    "entries",
    [(("data.pkl", b"N."),), (("array.npy", npy()),), (("a.npy", npy()), ("b.npy", npy()))],
)
def test_real_zip_and_npz(method, entries):
    data = archive(entries, method)
    report = review_bytes(data)
    assert report["status"] == "PASS"
    assert report["counts"]["members"] == len(entries)
    assert report["counts"]["expanded_bytes"] == sum(len(payload) for _, payload in entries)


@pytest.mark.parametrize(
    "name",
    [
        "../private-name",
        "/private-name",
        "a/../private-name",
        "a\\private-name",
        "a\0private-name",
        "a//b",
        "a//",
        "CON",
        "a:",
        "a/．．/b",
        "a/／/b",
        "a\u00a0",
        "a\u0085b",
        "a\u2028b",
    ],
)
def test_zip_unsafe_paths(name):
    # zipfile itself truncates NUL; mutate a serialized name to retain raw NUL.
    if "\0" in name:
        data = archive((("a_private-name", b"N."),)).replace(b"a_private-name", b"a\0private-name")
    else:
        data = archive(((name, b"N."),))
    report = review_bytes(data)
    assert report["status"] == "FAIL"
    assert "private-name" not in json.dumps(report)


@pytest.mark.parametrize(
    "entries",
    [
        (("a.pkl", b"N."), ("a.pkl", b"N.")),
        (("A.pkl", b"N."), ("a.pkl", b"N.")),
        (("a", b"N."), ("a/b.pkl", b"N.")),
        (("a/b.pkl", b"N."), ("a", b"N.")),
    ],
)
def test_duplicate_case_and_prefix(entries):
    with (
        pytest.warns(UserWarning)
        if entries[0][0] == entries[1][0]
        else __import__("contextlib").nullcontext()
    ):
        data = archive(entries)
    assert review_bytes(data)["status"] == "FAIL"


@pytest.mark.parametrize("mode", (stat.S_IFLNK, stat.S_IFIFO, stat.S_IFCHR, stat.S_IFSOCK))
@pytest.mark.parametrize("platform", (0, 3))
def test_special_members(mode, platform):
    info = zipfile.ZipInfo("private-link.pkl")
    info.create_system = platform
    info.external_attr = (mode | 0o600) << 16
    report = review_bytes(archive(((info, b"N."),)))
    assert report["status"] == "FAIL"
    assert "private-link" not in json.dumps(report)


def test_opaque_member_and_nested_zip_open():
    report = review_bytes(archive((("model/data.pkl", b"N."), ("model/data/0", b"opaque"))))
    assert report["status"] == "OPEN"
    assert "zip_opaque_entry_unvalidated" in codes(report)
    assert "nested_zip_unsupported" in codes(review_bytes(archive((("nested.zip", archive()),))))
    assert review_bytes(archive(()))["status"] == "OPEN"
    assert review_bytes(archive((("array.npy", npy("|O", (1,), b"N.")),)))["status"] == "OPEN"
    assert review_bytes(archive((("array.npy", b"N."),)))["status"] == "OPEN"


@pytest.mark.parametrize("flags", (1, 0x20, 0x40, 0x100))
def test_zip_flags(flags):
    raw = bytearray(archive())
    central = raw.index(b"PK\x01\x02")
    struct.pack_into("<H", raw, 6, flags)
    struct.pack_into("<H", raw, central + 8, flags)
    assert review_bytes(bytes(raw))["status"] == "OPEN"


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d[:-1],
        lambda d: b"x" + d,
        lambda d: d + b"x",
        lambda d: d.replace(b"N.", b"X.", 1),
        lambda d: d[:30] + b"X" + d[31:],
    ],
)
def test_zip_corruption(change):
    assert review_bytes(change(archive()))["status"] == "OPEN"


def descriptor_zip(signed=True, local_tuple=(0, 0, 0), method=0, needed=20):
    name, payload = b"data.pkl", b"N."
    raw = payload if method == 0 else zlib.compress(payload)[2:-4]
    crc, compressed, size = zlib.crc32(payload), len(raw), len(payload)
    local = struct.pack(
        "<4s5H3I2H", b"PK\x03\x04", needed, 8, method, 0, 0, *local_tuple, len(name), 0
    )
    descriptor = (b"PK\x07\x08" if signed else b"") + struct.pack("<3I", crc, compressed, size)
    body = local + name + raw + descriptor
    central = (
        struct.pack(
            "<4s6H3I5H2I",
            b"PK\x01\x02",
            20,
            needed,
            8,
            method,
            0,
            0,
            crc,
            compressed,
            size,
            len(name),
            0,
            0,
            0,
            0,
            0,
            0,
        )
        + name
    )
    return (
        body
        + central
        + struct.pack("<4s4H2IH", b"PK\x05\x06", 0, 0, 1, 1, len(central), len(body), 0)
    )


@pytest.mark.parametrize("signed", (False, True))
@pytest.mark.parametrize("method", (0, 8))
def test_descriptor_signed_unsigned(signed, method):
    assert review_bytes(descriptor_zip(signed, method=method))["status"] == "PASS"


@pytest.mark.parametrize("signed", (False, True))
@pytest.mark.parametrize("local_tuple", ((1, 0, 0), (0, 99, 0), (0, 0, 99)))
def test_descriptor_contradictory_local_tuple(signed, local_tuple):
    assert review_bytes(descriptor_zip(signed, local_tuple))["status"] == "OPEN"


def test_deflate_version_and_exact_eof():
    assert review_bytes(descriptor_zip(method=8, needed=10))["status"] == "OPEN"
    raw = bytearray(archive(method=8))
    raw[38] = 255
    assert review_bytes(bytes(raw))["status"] == "OPEN"


@pytest.mark.parametrize(
    "field,value,data",
    [
        ("member_bytes", 1, archive()),
        ("expanded_bytes", 1, archive()),
        ("members", 1, archive((("a.pkl", b"N."), ("b.pkl", b"N.")))),
        ("npy_header", 1, npy()),
        ("npy_ast_nodes", 1, npy()),
        ("npy_depth", 1, npy()),
    ],
)
def test_container_budgets(field, value, data):
    report = review_bytes(data, limits=replace(Limits(), **{field: value}))
    assert report["status"] == "OPEN"


@pytest.mark.parametrize("data", (b"7z\xbc\xaf\x27\x1cstuff", b"\x1f\x8bcompressed", b"USTARdata"))
def test_unsupported_containers(data):
    assert review_bytes(data)["status"] == "OPEN"
