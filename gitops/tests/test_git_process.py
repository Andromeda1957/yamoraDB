"""Owned helper lifecycle and typed command rejection, using real child processes."""

import os
import signal
import sys
import time
import unittest
from unittest.mock import patch

from yamora.gitops.git_writer import GitInfrastructureError
from yamora.gitops.git_writer import _Child
from yamora.gitops.git_writer import _members
from yamora.gitops.model import PlanError
from yamora.gitops.tests.test_git_signing import SyntheticGit


class GitProcessTests(SyntheticGit, unittest.TestCase):
    def child(self, script, maximum=4096):
        return _Child(
            [sys.executable, "-c", script],
            cwd=self.root,
            env=self.env,
            end=time.monotonic() + 5,
            maximum=maximum,
            retain=lambda: self.fail("unexpected unverified helper cleanup"),
        )

    def test_output_limit_is_enforced_while_child_runs_and_child_is_reaped(self):
        child = self.child("import sys; sys.stdout.buffer.write(b'x'*4096)", maximum=64)
        with self.assertRaisesRegex(GitInfrastructureError, "byte limit"):
            try:
                child.finish()
            finally:
                child.close()
        with self.assertRaises(ProcessLookupError):
            os.kill(child.process.pid, 0)

    def test_exited_leader_descendant_is_stopped_before_workspace_cleanup(self):
        script = (
            "import os,signal,time; "
            "signal.pthread_sigmask(signal.SIG_UNBLOCK,{signal.SIGINT,signal.SIGTERM}); "
            "pid=os.fork(); "
            "\nif pid==0:\n os.close(1); os.close(2); time.sleep(30); os._exit(0)"
            "\nprint(pid,flush=True)\nos._exit(0)"
        )
        child = self.child(script)
        descendant_fd = None
        try:
            code, output = child.finish()
            self.assertEqual(code, 0)
            descendant = int(output.strip())
            descendant_fd = os.pidfd_open(descendant)
            self.assertIn(descendant, _members(child.process.pid), "DESCENDANT_WITNESS")
            child.close()
            self.assertEqual(_members(child.process.pid), [], "DESCENDANT_SURVIVED_LEADER")
        finally:
            if descendant_fd is not None:
                try:
                    signal.pidfd_send_signal(descendant_fd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                deadline = time.monotonic() + 5
                while _members(child.process.pid) and time.monotonic() < deadline:
                    time.sleep(0.01)
                if _members(child.process.pid):
                    raise GitInfrastructureError("fixture descendant stop unverified")
                os.close(descendant_fd)
            child.close()

    def test_constructor_handoff_sigint_reaps_before_return(self):
        import subprocess

        original = subprocess.Popen
        children = []

        def launch(*args, **kwargs):
            process = original(*args, **kwargs)
            children.append(process)
            os.kill(os.getpid(), signal.SIGINT)
            return process

        with patch("yamora.gitops.git_writer.subprocess.Popen", side_effect=launch):
            with self.assertRaises(KeyboardInterrupt):
                self.child(
                    "import signal,time; signal.pthread_sigmask(signal.SIG_UNBLOCK,{signal.SIGTERM}); time.sleep(30)"
                )
        self.assertEqual(len(children), 1)
        with self.assertRaises(ProcessLookupError):
            os.kill(children[0].pid, 0)

    def test_writer_rejects_unsafe_argv_before_process_creation(self):
        with (
            self.writer() as writer,
            patch(
                "yamora.gitops.git_writer.subprocess.Popen",
                side_effect=AssertionError("UNSAFE_ARGV_EXECUTED"),
            ),
        ):
            for args in (
                ["checkout", "HEAD"],
                ["update-ref", "--stdin", "-z", "--create-reflog"],
                ["hash-object", "-w", "--stdin", "--path=owned.yaml"],
                ["commit-tree", "--help", "-p", "a" * 40, "-S"],
                ["show-ref", "--verify", "--hash", "refs/heads/fixture"],
                ["symbolic-ref", "--quiet", "--delete"],
            ):
                with self.subTest(args=args), self.assertRaises(PlanError):
                    with writer.launch(args):
                        self.fail("unsafe command admitted")

    def test_sigterm_cleanup_restores_previous_handler(self):
        previous = signal.getsignal(signal.SIGTERM)
        with self.assertRaises(KeyboardInterrupt):
            with self.writer() as writer:
                child = _Child(
                    [sys.executable, "-c", "import time; time.sleep(30)"],
                    cwd=self.root,
                    env=writer.env,
                    end=time.monotonic() + 5,
                    maximum=64,
                    retain=writer._retain,
                )
                try:
                    os.kill(os.getpid(), signal.SIGTERM)
                finally:
                    child.close()
        self.assertIs(signal.getsignal(signal.SIGTERM), previous)
        with self.assertRaises(ProcessLookupError):
            os.kill(child.process.pid, 0)

    def test_unverified_stop_retains_workspace(self):
        with self.writer() as writer:
            child = self.child("pass")
            child.finish()
            try:
                child.retain = writer._retain
                with patch(
                    "yamora.gitops.git_writer._members", side_effect=OSError("scan unavailable")
                ):
                    with self.assertRaisesRegex(GitInfrastructureError, "unverified"):
                        child.close()
                self.assertTrue(writer.retained)
                self.assertTrue(writer.work.is_dir(), "UNVERIFIED_WORKSPACE_REMOVED")
            finally:
                # The controlled process has exited; reap it without adopting another PID.
                child.process.wait(timeout=5)
                for stream in (child.process.stdin, child.process.stdout, child.process.stderr):
                    if not stream.closed:
                        stream.close()
                child.selector.close()
        self.assertTrue(writer.work.is_dir())
        # This fixture proved the only process stopped; clean its exact retained directory.
        import shutil

        shutil.rmtree(writer.work)

    def test_fork_child_cannot_control_inherited_parent_helper(self):
        child = self.child(
            "import signal,time; signal.pthread_sigmask(signal.SIG_UNBLOCK,{signal.SIGTERM}); time.sleep(30)"
        )
        child.retain = lambda: None
        reader, writer = os.pipe()
        forked = os.fork()
        if forked == 0:
            os.close(reader)
            try:
                child.close()
                os.write(writer, b"adopted")
            except GitInfrastructureError:
                os.write(writer, b"foreign-owner-rejected")
            finally:
                os._exit(0)
        os.close(writer)
        try:
            result = os.read(reader, 128)
            os.waitpid(forked, 0)
            self.assertIsNone(child._status(), "FOREIGN_OWNER_KILLED_PARENT_HELPER")
            self.assertEqual(result, b"foreign-owner-rejected")
        finally:
            os.close(reader)
            child.close()

    def test_deadline_is_infrastructure_and_stops_owned_group(self):
        child = self.child(
            "import signal,time; signal.pthread_sigmask(signal.SIG_UNBLOCK,{signal.SIGTERM}); time.sleep(30)"
        )
        child.end = time.monotonic() + 0.02
        try:
            with self.assertRaisesRegex(GitInfrastructureError, "deadline"):
                child.finish()
        finally:
            child.close()
        with self.assertRaises(ProcessLookupError):
            os.kill(child.process.pid, 0)

    def test_internal_popen_interrupt_retains_workspace_and_signing_descriptor(self):
        import subprocess

        from yamora.gitops.signing import private_key

        original = subprocess.Popen
        launched = []

        class InterruptedPopen(original):
            def _execute_child(process, *args, **kwargs):
                super()._execute_child(*args, **kwargs)
                launched.append(process)
                raise KeyboardInterrupt("synthetic interruption inside Popen")

        config, public = self.make_key()
        writer = self.writer(public)
        pinned_fd = None
        pinned_identity = None
        failure = None
        try:
            try:
                with writer:
                    with private_key(config, writer) as path:
                        pinned_fd = int(path.rsplit("/", 1)[1])
                        value = os.fstat(pinned_fd)
                        pinned_identity = (value.st_dev, value.st_ino)
                        with patch("yamora.gitops.git_writer.subprocess.Popen", InterruptedPopen):
                            _Child(
                                [sys.executable, "-c", "import time; time.sleep(30)"],
                                cwd=self.root,
                                env=writer.env,
                                end=time.monotonic() + 5,
                                maximum=64,
                                retain=writer._retain,
                            )
            except (KeyboardInterrupt, GitInfrastructureError) as error:
                failure = error
            self.assertEqual(len(launched), 1, "REAL_INTERNAL_LAUNCH_REQUIRED")
            self.assertIn(launched[0].pid, _members(launched[0].pid), "OWNED_LAUNCH_MUST_BE_LIVE")
            self.assertTrue(writer.retained, "GIT_LAUNCH_UNVERIFIED_MUST_RETAIN")
            self.assertTrue(writer.work.is_dir(), "GIT_LAUNCH_WORKSPACE_REMOVED")
            value = os.fstat(pinned_fd)
            self.assertEqual(
                (value.st_dev, value.st_ino),
                pinned_identity,
                "GIT_LAUNCH_SIGNING_DESCRIPTOR_CLOSED",
            )
            self.assertIsInstance(failure, GitInfrastructureError)
            self.assertIsInstance(failure.__context__, KeyboardInterrupt)
        finally:
            self.cleanup_unreturned_launch(writer, launched, pinned_fd, pinned_identity)

    def cleanup_unreturned_launch(self, writer, launched, pinned_fd, pinned_identity):
        # Only this fixture has real handles; production must not guess them.
        try:
            for process in launched:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                end = time.monotonic() + 5
                while _members(process.pid) and time.monotonic() < end:
                    time.sleep(0.01)
                if _members(process.pid):
                    raise GitInfrastructureError("internal-launch fixture stop unverified")
                process.wait(timeout=5)
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None and not stream.closed:
                        stream.close()
        except BaseException:
            self.temporary._finalizer.detach()
            raise
        if pinned_fd is not None:
            try:
                value = os.fstat(pinned_fd)
            except OSError:
                pass
            else:
                if (value.st_dev, value.st_ino) == pinned_identity:
                    os.close(pinned_fd)
        writer.workspace.cleanup()

    def test_writer_constructor_handoff_interrupt_retains_unknown_launch(self):
        from yamora.gitops.signing import private_key

        real_child = _Child
        launched = []

        def interrupt_before_handoff(*args, **kwargs):
            child = real_child(*args, **kwargs)
            launched.append(child.process)
            children.append(child)
            raise KeyboardInterrupt("synthetic interruption before writer handoff")

        config, public = self.make_key()
        writer = self.writer(public)
        children = []
        pinned_fd = None
        pinned_identity = None
        failure = None
        try:
            try:
                with writer:
                    with private_key(config, writer) as path:
                        pinned_fd = int(path.rsplit("/", 1)[1])
                        value = os.fstat(pinned_fd)
                        pinned_identity = (value.st_dev, value.st_ino)
                        with (
                            patch(
                                "yamora.gitops.git_writer._Child",
                                side_effect=interrupt_before_handoff,
                            ),
                            patch.object(
                                writer,
                                "_retain",
                                side_effect=KeyboardInterrupt(
                                    "synthetic interruption before retention callback"
                                ),
                            ),
                        ):
                            with writer.launch(["update-ref", "--stdin", "-z"]):
                                self.fail("UNRETURNED_LAUNCH_ENTERED_TRANSACTION")
            except (KeyboardInterrupt, GitInfrastructureError) as error:
                failure = error
            self.assertEqual(len(launched), 1, "REAL_WRITER_LAUNCH_REQUIRED")
            self.assertIn(
                launched[0].pid, _members(launched[0].pid), "OWNED_WRITER_LAUNCH_MUST_BE_LIVE"
            )
            self.assertTrue(writer.retained, "GIT_WRITER_LAUNCH_UNVERIFIED_MUST_RETAIN")
            self.assertTrue(writer.work.is_dir(), "GIT_WRITER_LAUNCH_WORKSPACE_REMOVED")
            value = os.fstat(pinned_fd)
            self.assertEqual(
                (value.st_dev, value.st_ino),
                pinned_identity,
                "GIT_WRITER_LAUNCH_SIGNING_DESCRIPTOR_CLOSED",
            )
            self.assertIsInstance(failure, KeyboardInterrupt)
            with patch(
                "yamora.gitops.git_writer.subprocess.Popen",
                side_effect=AssertionError("unverified writer attempted another launch"),
            ) as launch:
                try:
                    writer.run(["rev-parse", "--show-object-format"])
                except GitInfrastructureError:
                    pass
                self.assertFalse(launch.called, "GIT_UNKNOWN_LAUNCH_MUST_NOT_REDISPATCH")
        finally:
            self.cleanup_unreturned_launch(writer, launched, pinned_fd, pinned_identity)
            for child in children:
                child.selector.close()

    def test_interrupted_teardown_retains_before_key_unwinds_and_rejects_repeat_close(self):
        from yamora.gitops.signing import private_key

        config, public = self.make_key()
        writer = self.writer(public)
        launched, children = [], []
        pinned_fd = None
        pinned_identity = None
        failure = None

        def interrupt_after_closed(child, name, value):
            object.__setattr__(child, name, value)
            if name == "closed" and value is True:
                raise KeyboardInterrupt("synthetic interruption after marking closed")

        try:
            try:
                with writer:
                    with private_key(config, writer) as path:
                        pinned_fd = int(path.rsplit("/", 1)[1])
                        value = os.fstat(pinned_fd)
                        pinned_identity = (value.st_dev, value.st_ino)
                        with patch.object(_Child, "__setattr__", interrupt_after_closed):
                            with writer.launch(["update-ref", "--stdin", "-z"]) as child:
                                children.append(child)
                                launched.append(child.process)
            except (KeyboardInterrupt, GitInfrastructureError) as error:
                failure = error
            self.assertEqual(len(launched), 1, "REAL_TEARDOWN_LAUNCH_REQUIRED")
            self.assertTrue(children[0].closed, "TEARDOWN_CLOSED_MARKER_WITNESS")
            self.assertIn(
                launched[0].pid, _members(launched[0].pid), "INTERRUPTED_TEARDOWN_LIVE_WITNESS"
            )
            self.assertTrue(writer.retained, "GIT_INTERRUPTED_TEARDOWN_MUST_RETAIN")
            self.assertTrue(writer.work.is_dir(), "GIT_TEARDOWN_WORKSPACE_REMOVED")
            try:
                value = os.fstat(pinned_fd)
            except OSError:
                self.fail("GIT_KEY_CLOSED_BEFORE_TEARDOWN_RETENTION")
            self.assertEqual((value.st_dev, value.st_ino), pinned_identity)
            self.assertIsInstance(failure, GitInfrastructureError)
            self.assertIsInstance(failure.__cause__, KeyboardInterrupt)
            with self.assertRaisesRegex(GitInfrastructureError, "unverified"):
                children[0].close()
            self.assertIn(
                launched[0].pid, _members(launched[0].pid), "REPEAT_CLOSE_CONTROLLED_UNKNOWN_STOP"
            )
        finally:
            self.cleanup_unreturned_launch(writer, launched, pinned_fd, pinned_identity)
            for child in children:
                child.selector.close()

    def test_combined_teardown_and_retention_interrupt_cannot_redispatch(self):
        from yamora.gitops.signing import private_key

        config, public = self.make_key()
        writer = self.writer(public)
        launched, children = [], []
        pinned_fd = None
        pinned_identity = None

        def interrupt_after_closed(child, name, value):
            object.__setattr__(child, name, value)
            if name == "closed" and value is True:
                raise KeyboardInterrupt("synthetic teardown interruption")

        try:
            try:
                with writer:
                    with private_key(config, writer) as path:
                        pinned_fd = int(path.rsplit("/", 1)[1])
                        value = os.fstat(pinned_fd)
                        pinned_identity = (value.st_dev, value.st_ino)
                        with (
                            patch.object(_Child, "__setattr__", interrupt_after_closed),
                            patch.object(
                                writer,
                                "_retain",
                                side_effect=KeyboardInterrupt(
                                    "synthetic retention callback interruption"
                                ),
                            ),
                        ):
                            with writer.launch(["update-ref", "--stdin", "-z"]) as child:
                                children.append(child)
                                launched.append(child.process)
            except KeyboardInterrupt:
                pass
            self.assertEqual(len(launched), 1, "COMBINED_REAL_LAUNCH_REQUIRED")
            self.assertIn(
                launched[0].pid,
                _members(launched[0].pid),
                "COMBINED_UNVERIFIED_GROUP_LIVE_WITNESS",
            )
            self.assertTrue(children[0].closed)
            self.assertTrue(children[0].launch_admitted)
            self.assertFalse(writer._retained, "COMBINED_RETENTION_CALLBACK_WAS_INTERRUPTED")
            self.assertEqual(len(writer.pending_launches), 1)
            self.assertEqual(len(writer.children), 1, "COMBINED_EQUAL_COUNTS_WITNESS")
            self.assertTrue(writer.work.is_dir())
            value = os.fstat(pinned_fd)
            self.assertEqual((value.st_dev, value.st_ino), pinned_identity)
            with patch(
                "yamora.gitops.git_writer.subprocess.Popen",
                side_effect=AssertionError("combined interruption allowed another launch"),
            ) as launch:
                try:
                    writer.run(["rev-parse", "--show-object-format"])
                except GitInfrastructureError:
                    pass
                self.assertFalse(launch.called, "GIT_CLOSED_UNVERIFIED_CHILD_MUST_BLOCK_DISPATCH")
        finally:
            self.cleanup_unreturned_launch(writer, launched, pinned_fd, pinned_identity)
            for child in children:
                child.selector.close()

    def test_prepared_transaction_allows_two_live_registered_helpers(self):
        from yamora.gitops.tests.test_git_signing import TARGET

        current = self.commit({"x": b"x: 1"})
        self.git("update-ref", TARGET, current)
        with self.writer() as writer:
            with writer.launch(["update-ref", "--stdin", "-z"]) as transaction:
                transaction.send(b"start\0")
                transaction.expect(b"start: ok\n")
                transaction.send(
                    b"option no-deref\0update "
                    + TARGET.encode()
                    + b"\0"
                    + current.encode()
                    + b"\0"
                    + current.encode()
                    + b"\0prepare\0"
                )
                transaction.expect(b"prepare: ok\n")
                try:
                    with writer.launch(["update-ref", "--stdin", "-z"]) as nested:
                        nested.send(b"start\0")
                        nested.expect(b"start: ok\n")
                        self.assertNotEqual(nested.process.pid, transaction.process.pid)
                        for child in (transaction, nested):
                            self.assertIn(
                                child.process.pid,
                                _members(child.process.pid),
                                "LEGITIMATE_TWO_LIVE_HELPERS_WITNESS",
                            )
                        self.assertEqual(nested.finish()[0], 0)
                except GitInfrastructureError as error:
                    self.fail("LEGITIMATE_NESTED_HELPER_REJECTED: " + str(error))
                self.assertEqual(transaction.finish()[0], 0)
            self.assertFalse(writer.retained)
        self.assertEqual(
            self.git("show-ref", "--verify", "--hash", TARGET).stdout.strip().decode(), current
        )
        self.assertFalse((self.repo / ".git" / (TARGET + ".lock")).exists())
