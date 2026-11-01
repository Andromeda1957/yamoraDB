"""Pure Raft metadata decoding, fatal sanitizers and validator-removal probes."""

import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SANITIZER = os.environ.get("YAMORA_METADATA_SANITIZER", "address,undefined")


def compile_fixture(binary, source):
    subprocess.run(
        [
            os.environ.get("CC", "cc"),
            "-std=c17",
            "-O1",
            "-g",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            f"-fsanitize={SANITIZER}",
            "-fno-sanitize-recover=all",
            "-fno-omit-frame-pointer",
            "-ffunction-sections",
            "-fdata-sections",
            "-I",
            str(ROOT / "src/consensus"),
            str(ROOT / "tests/raft_metadata_decode.c"),
            str(source),
            str(ROOT / "src/consensus/journal_scope.c"),
            "-Wl,--gc-sections",
            "-pthread",
            *shlex.split(os.environ.get("YAMORA_METADATA_CFLAGS", "")),
            "-o",
            str(binary),
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )


def run_fixture(binary, scenario):
    return subprocess.run(
        [str(binary), scenario],
        capture_output=True,
        text=True,
        timeout=30,
        env={
            **os.environ,
            "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1:abort_on_error=1",
            "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
            # No inherited suppression file/options; races are fatal.
            "TSAN_OPTIONS": "halt_on_error=1:exitcode=66",
        },
    )


class RaftMetadataDecodeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.directory = Path(temporary.name)
        cls.binary = cls.directory / "raft-metadata-decode"
        compile_fixture(cls.binary, ROOT / "src/consensus/raft_store.c")

    def scenario(self, name):
        result = run_fixture(self.binary, name)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_legacy_modern_selected_and_extreme_valid_boundaries(self):
        self.scenario("valid")

    def test_exact_magic_lengths_all_truncations_and_reserved_bytes(self):
        self.scenario("framing")

    def test_cluster_node_voters_and_invalid_expected_values(self):
        self.scenario("identity")

    def test_term_vote_log_commit_and_snapshot_bounds(self):
        self.scenario("bounds")

    def test_zero_hashes_reject_and_independent_nonzero_hashes_decode_only(self):
        self.scenario("hashes")

    def test_null_failure_clearing_aliases_and_stale_expected_state(self):
        self.scenario("outputs")

    def test_independent_parallel_calls(self):
        self.scenario("parallel")

    def test_validator_removal_mutants_are_rejected_by_behavioral_tests(self):
        source = (ROOT / "src/consensus/raft_store.c").read_text()
        # Restrict edits to the pure decoder; startup remains untouched.
        start = source.index("bool yd_raft_decode_meta(")
        end = source.index("size_t yd_raft_encode_meta(", start)
        decoder = source[start:end]
        mutants = (
            ("legacy-length", "size == 64", "size >= 64", "framing"),
            ("magic", '!memcmp(bytes, "YDRMETA3", 8)', "true", "framing"),
            ("reserved", "if (bytes[i])", "if (false)", "framing"),
            ("cluster", "!memcmp(bytes + 8, m.cluster, 16)", "true", "identity"),
            ("node", "bytes[24] == m.node", "true", "identity"),
            ("voters", "bytes[25] == m.voters", "true", "identity"),
            ("vote", "m.vote <= m.voters", "true", "bounds"),
            ("last", "m.last < UINT64_MAX", "true", "bounds"),
            ("commit", "m.committed <= m.last", "true", "bounds"),
            ("term", "(m.term || (!m.vote && !m.last))", "true", "bounds"),
            ("snapshot-index", "m.snapshot.index &&", "true &&", "bounds"),
            ("snapshot-limit", "m.snapshot.index <= UINT64_MAX - 2", "true", "bounds"),
            ("snapshot-commit", "m.snapshot.index <= m.committed", "true", "bounds"),
            ("snapshot-term", "m.snapshot.term &&", "true &&", "bounds"),
            ("snapshot-current-term", "m.snapshot.term <= m.term", "true", "bounds"),
            ("archive-hash", "nonzero(m.snapshot.archive)", "true", "hashes"),
            ("application-hash", "nonzero(m.application)", "true", "hashes"),
            ("failure-clear", "memset(out, 0, sizeof(*out));", "(void)out;", "outputs"),
            # This break recreates the stale-expected-state hazard of a naive extraction.
            ("stale-state", "YDRaftMeta m = {0};", "YDRaftMeta m = *expected_identity;", "valid"),
        )
        for name, before, after, scenario in mutants:
            with self.subTest(mutant=name):
                self.assertEqual(decoder.count(before), 1, before)
                with tempfile.TemporaryDirectory() as temporary:
                    directory = Path(temporary)
                    mutated = directory / "raft_store.c"
                    mutated.write_text(
                        source[:start] + decoder.replace(before, after) + source[end:]
                    )
                    binary = directory / "mutant"
                    compile_fixture(binary, mutated)
                    result = run_fixture(binary, scenario)
                    # Require the assertion failure, not a crash/tool/sanitizer failure.
                    self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                    self.assertIn("line ", result.stderr)
