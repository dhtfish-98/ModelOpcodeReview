"""Public local-byte API. Content never selects target imports or callables."""

from .containers import analyze_npy, analyze_zip
from .contracts import Evidence, Incomplete, Limits
from .files import read_regular
from .opcodes import analyze_pickle


def _inspect(data, evidence, member=0, name="", in_zip=False, requested="auto"):
    if requested == "npy" or (
        requested == "auto"
        and (data.startswith(b"\x93NUMPY") or (in_zip and name.lower().endswith(".npy")))
    ):
        analyze_npy(data, evidence, member)
    elif requested == "zip" or (
        requested == "auto" and data.startswith((b"PK\x03\x04", b"PK\x05\x06"))
    ):
        if in_zip:
            evidence.emit("nested_zip_unsupported", member=member)
        else:
            analyze_zip(data, evidence, _inspect)
    elif requested == "pickle" or (
        requested == "auto"
        and (
            not in_zip
            or name.lower().endswith((".pkl", ".pickle", ".npy"))
            or data.startswith(b"\x80")
        )
    ):
        if data.startswith((b"7z\xbc\xaf\x27\x1c", b"\x1f\x8b")):
            evidence.emit("unsupported_compressed_container", member=member)
        else:
            analyze_pickle(data, evidence, member)
    else:
        # Tensor storage, JSON, code, version and arbitrary unknown ZIP entries
        # all remain unvalidated. No magic/name shortcut proves a complete model.
        evidence.emit("zip_opaque_entry_unvalidated", member=member)


def review_bytes(data, *, format="auto", limits=None):
    """Review immutable bytes; PASS only denotes complete selected static checks."""
    if type(data) is not bytes:
        raise ValueError("bytes_required")
    limits = Limits() if limits is None else limits
    if type(limits) is not Limits:
        raise ValueError("limits_required")
    limits.validate()
    evidence = Evidence(limits)
    detected = (
        (
            "npy"
            if data.startswith(b"\x93NUMPY")
            else "zip"
            if data.startswith((b"PK\x03\x04", b"PK\x05\x06"))
            else "pickle"
        )
        if format == "auto"
        else format
    )
    if type(format) is not str or format not in {"auto", "pickle", "zip", "npy"}:
        evidence.emit("unsupported_format")
    elif len(data) > limits.input_bytes:
        evidence.emit("budget_input_bytes")
    else:
        try:
            _inspect(data, evidence, requested=format)
        except Incomplete as exc:
            # Reserve a final reason even if the finding budget was exhausted.
            evidence.open = True
            if len(evidence.findings) < limits.findings:
                evidence.emit(str(exc))
        except (ValueError, SyntaxError, UnicodeError, OverflowError, EOFError, RecursionError):
            evidence.open = True
            if len(evidence.findings) < limits.findings:
                evidence.emit("invalid_or_unsupported_container")
    report = evidence.finish(
        data,
        detected if type(detected) is str and detected in {"pickle", "zip", "npy"} else "unknown",
    )
    return report


def review_file(path, *, format="auto", limits=None):
    limits = Limits() if limits is None else limits
    if type(limits) is not Limits:
        raise ValueError("limits_required")
    limits.validate()
    try:
        data = read_regular(path, limits.input_bytes)
    except (OSError, ValueError, TypeError, UnicodeError):
        evidence = Evidence(limits)
        evidence.emit("input_unavailable_or_unsafe")
        report = evidence.finish(b"", "unknown")
        report["input_sha256"] = None
        report["input_bytes"] = None
        return report
    return review_bytes(data, format=format, limits=limits)
