"""Strict bounded ZIP32 and NPY evidence. Never extract or instantiate arrays."""

import ast
import re
import stat
import struct
import unicodedata
import warnings
import zlib
from hashlib import sha256

from .contracts import Incomplete
from .opcodes import analyze_pickle


def path_key(name):
    if not name or len(name.encode()) > 1024 or name.startswith("/") or "\\" in name:
        raise Incomplete("zip_path")
    if unicodedata.normalize("NFC", name) != name or any(
        ord(c) < 32 or ord(c) == 127 or unicodedata.category(c) in {"Cc", "Cf", "Cs", "Zl", "Zp"}
        for c in name
    ):
        raise Incomplete("zip_path")
    parts = (name[:-1] if name.endswith("/") else name).split("/")
    if len(parts) > 32:
        raise Incomplete("zip_path_depth")
    for part in parts:
        folded = unicodedata.normalize("NFKC", part).casefold()
        if not part or folded in {".", ".."} or any(c in folded for c in "/\\:"):
            raise Incomplete("zip_path")
        if folded.endswith((".", " ")) or folded.split(".")[0] in {
            "con",
            "prn",
            "aux",
            "nul",
            *["com" + str(x) for x in range(1, 10)],
            *["lpt" + str(x) for x in range(1, 10)],
        }:
            raise Incomplete("zip_path")
    return "/".join(unicodedata.normalize("NFKC", p).casefold() for p in parts)


def extras(raw):
    position = 0
    seen = set()
    while position < len(raw):
        if position + 4 > len(raw):
            raise Incomplete("zip_extra_truncated")
        kind, size = struct.unpack_from("<HH", raw, position)
        position += 4
        if kind in seen or position + size > len(raw):
            raise Incomplete("zip_extra_truncated_or_duplicate")
        seen.add(kind)
        # Known opaque alignment/timestamp fields; no sizes/offsets derive from
        # these fields. ZIP64 and all other extension semantics are unsupported.
        if kind == 0xFB:
            if any(x != 0x5A for x in raw[position : position + size]):
                raise Incomplete("zip_alignment_extra")
        elif kind == 0x5455:
            if not size or raw[position] & ~7 or size != 1 + 4 * raw[position].bit_count():
                raise Incomplete("zip_timestamp_extra")
        else:
            raise Incomplete("zip_unsupported_extra")
        position += size


def inflate(raw, method, expected, evidence):
    if expected > evidence.limits.member_bytes:
        raise Incomplete("budget_member_bytes")
    if method == 0:
        value = raw
    elif method == 8:
        decoder = zlib.decompressobj(-15)
        try:
            value = decoder.decompress(raw, expected + 1)
        except zlib.error as exc:
            raise Incomplete("zip_deflate_invalid") from exc
        if (
            len(value) != expected
            or not decoder.eof
            or decoder.unused_data
            or decoder.unconsumed_tail
        ):
            raise Incomplete("zip_deflate_length_or_eof")
    else:
        raise Incomplete("zip_unsupported_method")
    if len(value) != expected:
        raise Incomplete("zip_member_length")
    evidence.charge("expanded_bytes", len(value))
    return value


def analyze_zip(data, evidence, inspect):
    # Reject appended bytes, preambles, gaps, ZIP64, multipart and encryption.
    # A comment can contain an EOCD marker; find a unique physically final EOCD.
    candidates = []
    for i in range(max(0, len(data) - 65557), max(0, len(data) - 21)):
        if data[i : i + 4] == b"PK\x05\x06" and i + 22 <= len(data):
            row = struct.unpack_from("<4s4H2IH", data, i)
            if i + 22 + row[7] == len(data):
                candidates.append((i, row))
    if len(candidates) != 1:
        raise Incomplete("zip_eocd")
    eocd_pos, end = candidates[0]
    if end[1:3] != (0, 0) or end[3] != end[4] or end[4] == 65535:
        raise Incomplete("zip_multidisk_or_zip64")
    if end[4] > evidence.limits.members or end[5] == 0xFFFFFFFF or end[6] == 0xFFFFFFFF:
        raise Incomplete("budget_members_or_zip64")
    if end[6] + end[5] != eocd_pos:
        raise Incomplete("zip_central_span")
    central, physical = end[6], 0
    seen = {}
    for member in range(1, end[4] + 1):
        evidence.charge("members")
        if central + 46 > eocd_pos or data[central : central + 4] != b"PK\x01\x02":
            raise Incomplete("zip_central_header")
        row = struct.unpack_from("<4s6H3I5H2I", data, central)
        made, needed, flags, method = row[1:5]
        crc, compressed, size = row[7:10]
        name_len, extra_len, comment_len = row[10:13]
        external, offset = row[15:17]
        if row[13] or 0xFFFFFFFF in {compressed, size, offset}:
            raise Incomplete("zip_multidisk_or_zip64")
        if made >> 8 not in {0, 3, 19} or needed not in {10, 20} or (method == 8 and needed < 20):
            raise Incomplete("zip_platform_or_version")
        if flags & ~(0x800 | 8) or (flags & 8 and needed < 20):
            raise Incomplete("zip_flags")
        stop = central + 46 + name_len + extra_len + comment_len
        if stop > eocd_pos or name_len > 1024 or extra_len > 4096:
            raise Incomplete("zip_central_length")
        raw_name = data[central + 46 : central + 46 + name_len]
        name_hash = sha256(raw_name).hexdigest()
        name = raw_name.decode("utf-8" if flags & 0x800 else "cp437", "strict")
        try:
            key = path_key(name)
        except Incomplete as exc:
            evidence.emit(str(exc), "FAIL", member=member, name_sha256=name_hash)
            key = None
        directory = name.endswith("/")
        mode = external >> 16
        kind = stat.S_IFMT(mode)
        if (
            kind not in {0, stat.S_IFREG, stat.S_IFDIR}
            or (kind == stat.S_IFDIR) != directory
            and kind
        ):
            evidence.emit("zip_link_special_or_type", "FAIL", member=member, name_sha256=name_hash)
        if external & 0x10 and not directory:
            evidence.emit("zip_dos_directory_type", "FAIL", member=member, name_sha256=name_hash)
        if key is not None:
            if key in seen:
                evidence.emit(
                    "zip_duplicate_or_case_alias", "FAIL", member=member, name_sha256=name_hash
                )
            for prefix, is_dir in seen.items():
                if (key.startswith(prefix + "/") and not is_dir) or (
                    prefix.startswith(key + "/") and not directory
                ):
                    evidence.emit(
                        "zip_file_directory_conflict", "FAIL", member=member, name_sha256=name_hash
                    )
            seen[key] = directory
        extras(data[central + 46 + name_len : central + 46 + name_len + extra_len])
        if offset != physical or offset + 30 > end[6] or data[offset : offset + 4] != b"PK\x03\x04":
            raise Incomplete("zip_local_offset_or_header")
        local = struct.unpack_from("<4s5H3I2H", data, offset)
        local_name_len, local_extra_len = local[9:11]
        begin = offset + 30 + local_name_len + local_extra_len
        if local[1:6] != row[2:7] or begin + compressed > end[6] or local_extra_len > 4096:
            raise Incomplete("zip_local_central_mismatch")
        if data[offset + 30 : offset + 30 + local_name_len] != raw_name:
            raise Incomplete("zip_local_name_mismatch")
        extras(data[offset + 30 + local_name_len : begin])
        if flags & 8:
            if local[6:9] not in {(0, 0, 0), (crc, compressed, size)}:
                raise Incomplete("zip_descriptor_local_mismatch")
        elif local[6:9] != (crc, compressed, size):
            raise Incomplete("zip_local_size_crc_mismatch")
        physical = begin + compressed
        if flags & 8:
            # Parse both possible descriptor widths, with exact central tuples.
            options = []
            if physical + 12 <= end[6] and struct.unpack_from("<3I", data, physical) == (
                crc,
                compressed,
                size,
            ):
                options.append(physical + 12)
            if (
                data[physical : physical + 4] == b"PK\x07\x08"
                and physical + 16 <= end[6]
                and struct.unpack_from("<3I", data, physical + 4) == (crc, compressed, size)
            ):
                options.append(physical + 16)
            if len(options) != 1:
                raise Incomplete("zip_data_descriptor")
            physical = options[0]
        payload = inflate(data[begin : begin + compressed], method, size, evidence)
        if zlib.crc32(payload) & 0xFFFFFFFF != crc:
            evidence.emit("zip_crc_mismatch", member=member, name_sha256=name_hash)
        if directory:
            if size:
                evidence.emit("zip_directory_payload", member=member, name_sha256=name_hash)
        else:
            inspect(payload, evidence, member, name, True)
        central = stop
    if central != eocd_pos or physical != end[6]:
        raise Incomplete("zip_unaccounted_bytes")
    if not end[4]:
        evidence.emit("zip_empty_no_model_entries")


def dimensions(shape):
    if type(shape) is not tuple or len(shape) > 32:
        raise Incomplete("npy_shape")
    count = 1
    for number in shape:
        if type(number) is not int or not 0 <= number <= 33554432:
            raise Incomplete("npy_shape")
        count *= number
        if count > 33554432:
            raise Incomplete("npy_element_budget")
    return count


def dtype(description, depth=0):
    if depth > 16:
        raise Incomplete("npy_dtype_depth")
    if isinstance(description, str):
        match = re.fullmatch(r"[<>=|]?([?biufcSUVaO])([0-9]{1,8})?", description)
        if not match:
            raise Incomplete("npy_unsupported_dtype")
        code, digits = match.groups()
        width = (
            int(digits) if digits is not None else 1 if code == "?" else 8 if code == "O" else None
        )
        if width is None or width < 0 or width > 8388608:
            raise Incomplete("npy_dtype_width")
        valid = {
            "?": {1},
            "b": {1},
            "i": {1, 2, 4, 8},
            "u": {1, 2, 4, 8},
            "f": {2, 4, 8, 16},
            "c": {8, 16, 32},
            "O": {4, 8},
        }
        if code in valid and width not in valid[code]:
            raise Incomplete("npy_dtype_width")
        return width * (4 if code == "U" else 1), code == "O"
    if type(description) is not list or not description or len(description) > 256:
        raise Incomplete("npy_unsupported_dtype")
    total, has_object, names = 0, False, set()
    for field in description:
        if type(field) is not tuple or len(field) not in {2, 3} or type(field[0]) is not str:
            raise Incomplete("npy_structured_dtype")
        if field[0] in names and field[0]:
            raise Incomplete("npy_duplicate_dtype_field")
        names.add(field[0])
        size, obj = dtype(field[1], depth + 1)
        if len(field) == 3:
            size *= dimensions(field[2])
        total += size
        has_object |= obj
        if total > 8388608:
            raise Incomplete("npy_dtype_width")
    return total, has_object


def analyze_npy(data, evidence, member=0):
    if (
        len(data) < 10
        or data[:6] != b"\x93NUMPY"
        or data[6:8] not in {b"\x01\0", b"\x02\0", b"\x03\0"}
    ):
        raise Incomplete("npy_magic_or_version")
    version = data[6]
    length_bytes = 2 if version == 1 else 4
    start = 8 + length_bytes
    if len(data) < start:
        raise Incomplete("npy_header_truncated")
    length = int.from_bytes(data[8:start], "little")
    if length > evidence.limits.npy_header or start + length > len(data) or not length:
        raise Incomplete("npy_header_length")
    end = start + length
    # 16-byte alignment accepts older writers as well as current 64-byte ones.
    if end % 16 or data[end - 1] != 10:
        raise Incomplete("npy_alignment_or_newline")
    text = data[start:end].decode("utf-8" if version == 3 else "latin1", "strict")
    # Parser warnings can contain fragments of the untrusted literal. Capture
    # them under any caller filter and expose only a fixed incomplete reason.
    with warnings.catch_warnings(record=True) as recorded:
        warnings.simplefilter("always")
        tree = ast.parse(text.strip(), mode="eval")
    if recorded:
        raise Incomplete("npy_compile_warning")
    stack, nodes = [(tree, 1)], 0
    while stack:
        node, depth = stack.pop()
        nodes += 1
        if nodes > evidence.limits.npy_ast_nodes or depth > evidence.limits.npy_depth:
            raise Incomplete("npy_ast_budget")
        stack.extend((child, depth + 1) for child in ast.iter_child_nodes(node))
    if not isinstance(tree.body, ast.Dict) or len(tree.body.keys) != 3:
        raise Incomplete("npy_header_schema")
    keys = [key.value if isinstance(key, ast.Constant) else None for key in tree.body.keys]
    if len(set(keys)) != 3 or set(keys) != {"descr", "fortran_order", "shape"}:
        raise Incomplete("npy_header_schema")
    header = ast.literal_eval(tree)
    if type(header["fortran_order"]) is not bool:
        raise Incomplete("npy_order")
    count = dimensions(header["shape"])
    width, objects = dtype(header["descr"])
    if objects:
        evidence.emit("npy_object_dtype", member=member, offset=end)
        analyze_pickle(data[end:], evidence, member, end)
    elif count * width != len(data) - end:
        raise Incomplete("npy_payload_length")
