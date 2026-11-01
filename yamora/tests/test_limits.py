"""Compile the native limits and compare them to Python's accepted capacity."""

import json
import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

from yamldb import validation


class LimitsParityTests(unittest.TestCase):
    def test_native_and_python_capacity_agree(self):
        native_names = (
            "DOCUMENT_LIMIT",
            "COLLECTION_LIMIT",
            "SNAPSHOT_DOCUMENT_LIMIT",
            "COLLECTION_DOCUMENT_LIMIT",
            "SNAPSHOT_BYTES_LIMIT",
        )
        python_values = [
            validation.MAX_DOCUMENT_BYTES,
            validation.MAX_COLLECTIONS,
            validation.MAX_SNAPSHOT_DOCUMENTS,
            validation.MAX_COLLECTION_DOCUMENTS,
            validation.MAX_SNAPSHOT_BYTES,
        ]
        statements = ",".join("(unsigned long long) YAMLDB_" + name for name in native_names)
        program = '#include <stdio.h>\n#include "snapshot.h"\nint main(void) {'
        program += (
            'printf("['
            + ",".join("%llu" for _ in native_names)
            + ']",'
            + statements
            + "); return 0;}\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "limits"
            subprocess.run(
                [
                    *shlex.split(os.environ.get("CC", "cc")),
                    "-std=c17",
                    "-Werror",
                    "-I",
                    str(Path(__file__).resolve().parents[1] / "src"),
                    "-x",
                    "c",
                    "-",
                    "-o",
                    str(binary),
                ],
                input=program,
                text=True,
                check=True,
            )
            native = json.loads(subprocess.check_output([str(binary)], text=True))
        self.assertEqual(native, python_values)
