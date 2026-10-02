"""Shared bounded evidence, with no source content in diagnostics."""

import json
from dataclasses import asdict, dataclass, fields
from hashlib import sha256


class Incomplete(ValueError):
    """A constant diagnostic code; never contains input text."""


@dataclass(frozen=True)
class Limits:
    input_bytes: int = 16777216
    member_bytes: int = 8388608
    expanded_bytes: int = 33554432
    members: int = 256
    opcodes: int = 100000
    nodes: int = 50000
    stack: int = 10000
    memo: int = 20000
    references: int = 100000
    work: int = 1000000
    operand_bytes: int = 2097152
    streams: int = 64
    findings: int = 512
    report_bytes: int = 262144
    npy_header: int = 32768
    npy_ast_nodes: int = 2048
    npy_depth: int = 32

    def validate(self):
        ceiling = Limits()
        for field in fields(self):
            value = getattr(self, field.name)
            if type(value) is not int or not 1 <= value <= getattr(ceiling, field.name):
                raise ValueError("invalid_limits")
        if self.report_bytes < 2048:
            raise ValueError("invalid_limits")


class Evidence:
    def __init__(self, limits):
        self.limits = limits
        self.fail = False
        self.open = False
        self.counts = {
            "opcodes": 0,
            "nodes": 0,
            "references": 0,
            "work": 0,
            "expanded_bytes": 0,
            "members": 0,
            "streams": 0,
        }
        self.findings = []

    def charge(self, name, amount=1):
        self.counts[name] += amount
        if self.counts[name] > getattr(self.limits, name):
            raise Incomplete("budget_" + name)

    def emit(self, code, status="OPEN", **location):
        self.open |= status == "OPEN"
        self.fail |= status == "FAIL"
        if len(self.findings) >= self.limits.findings:
            self.open = True
            raise Incomplete("budget_findings")
        self.findings.append({"code": code, "status": status, **location})

    def finish(self, data, kind):
        report = {
            "schema_version": "1",
            "rule_version": "model-opcode-review-1",
            "status": "FAIL" if self.fail else "OPEN" if self.open else "PASS",
            "analysis_completeness": "INCOMPLETE" if self.open else "COMPLETE",
            "format": kind,
            "input_sha256": sha256(data).hexdigest()
            if len(data) <= self.limits.input_bytes
            else None,
            "input_bytes": len(data),
            "limits": asdict(self.limits),
            "counts": self.counts,
            "findings": self.findings,
            "external": {
                "deserialization_safety": "OPEN",
                "runtime_bindings": "OPEN",
                "model_correctness": "OPEN",
                "authenticity": "OPEN",
                "cvp_eligibility": "OPEN",
            },
        }
        if len(json.dumps(report, ensure_ascii=True).encode()) > self.limits.report_bytes:
            report["status"] = "FAIL" if self.fail else "OPEN"
            report["analysis_completeness"] = "INCOMPLETE"
            report["findings"] = [{"code": "budget_report", "status": "OPEN"}]
        return report
