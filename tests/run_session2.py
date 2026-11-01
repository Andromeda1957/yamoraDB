"""Build one exact sanitizer candidate and execute Session 2 acceptance in managed scratch."""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULES = (
    "yamora.tests.test_raft_application",
    "yamora.tests.test_raft_index_jobs",
    "yamora.tests.test_raft_replica",
    "yamora.tests.test_cluster_backup",
    "yamora.tests.test_session2_cluster",
    "yamora.tests.test_session2_sharding",
    "yamora.tests.test_raft_membership",
    "yamora.tests.test_membership_controller",
    "yamora.tests.test_sharding",
    "yamora.tests.test_sharding_runtime",
    "yamora.tests.test_shard_service",
    "yamora.tests.test_query_analytics",
    "yamora.tests.test_joins",
    "yamora.tests.test_disk_aggregate",
    "yamora.tests.test_session2_faults",
    "yamora.tests.test_session2_stdio_mux",
    "yamora.tests.test_session2_two_host",
    "yamora.tests.test_session2_qualification",
    "yamora.tests.test_cluster_api.ClusterApiTests."
    "test_public_http_rejects_forged_internal_shard_control",
    "yamora.tests.test_cluster_api.ClusterApiTests."
    "test_public_http_cannot_fail_a_held_native_index_job",
    "yamora.tests.test_cluster_api.ClusterApiTests."
    "test_public_http_verbs_preserve_document_and_query_apis",
)


def main():
    with tempfile.TemporaryDirectory() as temporary:
        build = Path(temporary) / "native"
        environment = {
            **os.environ,
            "YAMLDB_BUILD_DIR": str(build),
            "CC": "clang",
            "SHARD_SERVICE_SANITIZED": "1",
            "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
            "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
        }
        subprocess.run(
            [
                "make",
                "--silent",
                "-j2",
                "-C",
                str(ROOT),
                f"BUILD_DIR={build}",
                "CC=clang",
                "CFLAGS=-std=c17 -O1 -g -Wall -Wextra -Wpedantic -Werror -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer",
                "LDLIBS=-pthread -fsanitize=address,undefined",
                "all",
                str(build / "yamora-session2"),
            ],
            check=True,
            env=environment,
        )
        subprocess.run(
            [sys.executable, "-m", "unittest", "-v", *(sys.argv[1:] or MODULES)],
            cwd=ROOT.parent,
            env=environment,
            check=True,
        )


if __name__ == "__main__":
    main()
