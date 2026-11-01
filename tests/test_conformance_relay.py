"""Relay startup interruption must not escape its resource ownership boundary."""

import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from yamora.conformance.tests.relay import Relay


class RelayLifetimeTests(unittest.TestCase):
    def test_interrupted_start_closes_listener_and_joins_started_thread(self):
        entered = threading.Event()

        def serve(relay):
            entered.set()
            relay.stop.wait(5)

        with patch.object(Relay, "serve", serve):
            relay = Relay(SimpleNamespace())
        original = relay.thread.start

        def interrupted_start():
            original()
            self.assertTrue(entered.wait(1), "a real relay thread must start")
            raise KeyboardInterrupt

        try:
            with patch.object(relay.thread, "start", side_effect=interrupted_start):
                with self.assertRaises(KeyboardInterrupt):
                    relay.__enter__()
            self.assertEqual(relay.listener.fileno(), -1, "RELAY_ENTER_MUST_RELEASE")
            self.assertFalse(relay.thread.is_alive(), "RELAY_ENTER_MUST_JOIN")
        finally:
            relay.__exit__(None, None, None)
