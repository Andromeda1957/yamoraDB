"""Observe acceptance commands without starting native builds or daemons."""

import contextlib
import unittest
from unittest.mock import patch

from tools.shared.scratch import temporary_directory
from yamora.tests import run_session2


class Session2RunnerTests(unittest.TestCase):
    def commands(self, *selection):
        with (
            temporary_directory(prefix="session2-runner-control-") as root,
            patch.object(
                run_session2.tempfile,
                "TemporaryDirectory",
                return_value=contextlib.nullcontext(str(root)),
            ),
            patch.object(run_session2.sys, "argv", ["run_session2.py", *selection]),
            patch.dict(run_session2.os.environ, {"SHARD_SERVICE_SANITIZED": "0"}),
            patch.object(run_session2.subprocess, "run") as execute,
        ):
            run_session2.main()
        self.assertEqual(execute.call_count, 2)
        return execute.call_args_list

    def test_default_suite_dispatches_all_three_public_method_regressions(self):
        commands = self.commands()
        selected = commands[1].args[0][4:]
        prefix = "yamora.tests.test_cluster_api.ClusterApiTests."
        methods = (
            "test_public_http_rejects_forged_internal_shard_control",
            "test_public_http_cannot_fail_a_held_native_index_job",
            "test_public_http_verbs_preserve_document_and_query_apis",
        )
        expected = [prefix + method for method in methods]
        self.assertTrue(set(expected).issubset(selected), selected)
        loaded = unittest.defaultTestLoader.loadTestsFromNames(expected)
        self.assertEqual(
            [test.id() for suite in loaded for test in suite],
            expected,
        )
        self.assertNotIn("yamora.tests.test_cluster_api", selected)

    def test_nested_shard_service_dispatch_has_sanitizers_enabled(self):
        commands = self.commands("yamora.tests.test_shard_service")
        for command in commands:
            environment = command.kwargs["env"]
            self.assertEqual(environment.get("SHARD_SERVICE_SANITIZED"), "1")
            self.assertEqual(environment["CC"], "clang")
            self.assertIn("halt_on_error=1", environment["ASAN_OPTIONS"])
            self.assertIn("halt_on_error=1", environment["UBSAN_OPTIONS"])

    def test_explicit_test_selection_preserves_the_requested_scope(self):
        selection = ("yamora.tests.test_shard_service", "yamora.tests.test_query_analytics")
        commands = self.commands(*selection)
        self.assertEqual(commands[1].args[0][4:], list(selection))
        self.assertTrue(commands[0].kwargs["check"])
        self.assertTrue(commands[1].kwargs["check"])
