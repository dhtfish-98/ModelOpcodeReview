"""Private constant diagnostics; one local regular file, no URL/directory walk."""

import argparse
import json

from .review import review_file


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError("arguments")


def main(argv=None):
    parser = Parser(description="Bounded offline pickle/ZIP/NPY static review; never deserialize")
    parser.add_argument("path")
    parser.add_argument("--format", choices=("auto", "pickle", "zip", "npy"), default="auto")
    parser.add_argument("--version", action="version", version="ModelOpcodeReview 0.1.3")
    try:
        args = parser.parse_args(argv)
        report = review_file(args.path, format=args.format)
    except (ValueError, OSError, TypeError, UnicodeError):
        report = {
            "schema_version": "1",
            "status": "OPEN",
            "analysis_completeness": "INCOMPLETE",
            "findings": [{"code": "arguments_or_input_error", "status": "OPEN"}],
            "external": {"deserialization_safety": "OPEN", "cvp_eligibility": "OPEN"},
        }
    print(json.dumps(report, sort_keys=True, ensure_ascii=True, separators=(",", ":")))
    return {"PASS": 0, "FAIL": 1, "OPEN": 2}[report["status"]]
