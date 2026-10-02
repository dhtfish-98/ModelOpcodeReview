"""Installed identity plus observed execution/import/network/write denial."""

import contextlib
import io
import json
import os
import sys
import zipfile
from pathlib import Path

import model_opcode_review
from model_opcode_review import review_bytes
from model_opcode_review.cli import main


def require(condition, message):
    if not condition:
        raise ValueError(message)


root = Path(__file__).resolve().parents[1]
wheel = Path(sys.argv[1]).resolve()
installed = Path(model_opcode_review.__file__).resolve().parent
require(Path(sys.prefix).resolve() in installed.parents, "not independently installed")
count = 0
with zipfile.ZipFile(wheel) as archive:
    for name in archive.namelist():
        if name.startswith("model_opcode_review/"):
            relative = name.removeprefix("model_opcode_review/")
            require((installed / relative).read_bytes() == archive.read(name), "installed mismatch")
            count += 1
cases = [
    (name, (root / "examples" / name).read_bytes(), status)
    for name, status in (
        ("primitive.pkl", "PASS"),
        ("primitive.npy", "PASS"),
        ("primitive.zip", "PASS"),
        ("global-declaration.pkl", "FAIL"),
        ("object-header.npy", "OPEN"),
        ("truncated.pkl", "OPEN"),
    )
]
# Preload trusted stdlib helpers. AST-only compile is used for NPY header parsing;
# execution events are forbidden. No input controls imports, even during warmup.
for _, data, _ in cases:
    review_bytes(data)
with contextlib.redirect_stdout(io.StringIO()):
    main([])
seen = {"exec": 0, "import": 0, "socket": 0, "process": 0, "write_open": 0}


def audit(event, arguments):
    kind = None
    if event == "exec":
        kind = "exec"
    elif event == "import":
        kind = "import"
    elif event.startswith("socket."):
        kind = "socket"
    elif event.startswith(("subprocess.", "os.exec", "os.spawn")) or event == "os.system":
        kind = "process"
    elif event == "open" and arguments[2] & (
        os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
    ):
        kind = "write_open"
    if kind:
        seen[kind] += 1
        raise RuntimeError("prohibited event")


sys.addaudithook(audit)
for _, data, expected in cases:
    require(review_bytes(data)["status"] == expected, "installed audit result")
with contextlib.redirect_stdout(io.StringIO()) as output:
    require(main([str(root / "examples/primitive.zip")]) == 0, "installed file CLI")
require(json.loads(output.getvalue())["status"] == "PASS", "CLI JSON")
require(not any(seen.values()), "prohibited event observed")
print(
    json.dumps(
        {
            "status": "PASS",
            "audit_cases": len(cases) + 1,
            "installed_runtime_files_verified": count,
            "prohibited_events": seen,
        },
        sort_keys=True,
    )
)
