"""Mandatory safe-open capabilities cannot silently degrade to ordinary opens."""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

CLI_DRIVER = """import os,sys
from model_opcode_review.cli import main
flag,mode=sys.argv[1:3]
if mode == "missing":delattr(os,flag)
else:setattr(os,flag,{"zero":0,"none":None,"bool":True,"text":"1","float":1.0}[mode])
raise SystemExit(main(sys.argv[3:]))
"""


class CapabilityTests(unittest.TestCase):
    def test_invalid_required_flags_are_controlled_before_io(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "snapshot"
            path.write_bytes(b"not read under unavailable capabilities")
            for flag in ("O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK"):
                for mode in ("missing", "zero", "none", "bool", "text", "float"):
                    old = getattr(os, flag)
                    try:
                        if mode == "missing":
                            delattr(os, flag)
                        else:
                            setattr(
                                os,
                                flag,
                                {"zero": 0, "none": None, "bool": True, "text": "1", "float": 1.0}[
                                    mode
                                ],
                            )
                        from model_opcode_review import review_file

                        result = review_file(path)
                        self.assertEqual(result["status"], "OPEN")
                        self.assertEqual(
                            result["findings"][0]["code"], "input_unavailable_or_unsafe"
                        )
                    finally:
                        setattr(os, flag, old)
                    process = subprocess.run(
                        [
                            sys.executable,
                            "-c",
                            CLI_DRIVER,
                            flag,
                            mode,
                            *[str(path)],
                        ],
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    self.assertEqual(process.returncode, 2)
                    self.assertNotIn("Traceback", process.stderr)
                    self.assertFalse(path.with_suffix(".new").exists())


if __name__ == "__main__":
    unittest.main()
