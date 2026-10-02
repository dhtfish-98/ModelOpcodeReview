"""Real console/module CLI in independent consumer environment."""

import json
import os
import subprocess
import sys
from pathlib import Path


def require(condition, message):
    if not condition:
        raise ValueError(message)


root = Path(__file__).resolve().parents[1]
console = Path(sys.executable).parent / "model-opcode-review"
environment = dict(os.environ)
environment.pop("PYTHONPATH", None)
cases = [
    ("primitive.pkl", "PASS", 0),
    ("primitive.npy", "PASS", 0),
    ("primitive.zip", "PASS", 0),
    ("global-declaration.pkl", "FAIL", 1),
    ("object-header.npy", "OPEN", 2),
    ("truncated.pkl", "OPEN", 2),
    ("PRIVATE_MISSING.pkl", "OPEN", 2),
]
for filename, status, code in cases:
    result = subprocess.run(
        [str(console), str(root / "examples" / filename)],
        cwd=Path(sys.prefix),
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    require(
        result.returncode == code and json.loads(result.stdout)["status"] == status,
        "console result",
    )
    require(
        not result.stderr
        and "PRIVATE_MISSING" not in result.stdout
        and str(root) not in result.stdout,
        "CLI disclosure",
    )
result = subprocess.run(
    [sys.executable, "-m", "model_opcode_review", str(root / "examples/primitive.zip")],
    cwd=Path(sys.prefix),
    env=environment,
    capture_output=True,
    text=True,
    timeout=10,
    check=False,
)
require(
    result.returncode == 0 and json.loads(result.stdout)["status"] == "PASS" and not result.stderr,
    "module result",
)
print(json.dumps({"status": "PASS", "installed_cli_cases": len(cases) + 1}, sort_keys=True))
