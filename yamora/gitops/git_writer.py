"""Typed Git plumbing with bounded byte pipes and owned process groups."""

from __future__ import annotations

import os
import re
import selectors
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import weakref
from contextlib import contextmanager
from pathlib import Path

from .git_reader import plain_path
from .model import PlanError

OID = r"(?:[0-9a-f]{40}|[0-9a-f]{64})"
REF = r"refs/yamora-gitops/targets/[A-Za-z0-9][A-Za-z0-9_-]{0,63}"


class GitInfrastructureError(RuntimeError):
    """The invocation or cleanup could not be qualified."""


class GitCommandError(PlanError):
    def __init__(self, code):
        super().__init__("bounded Git command rejected the operation")
        self.returncode = code


def repository_identity(repo, object_format):
    root = plain_path(repo, directory=True)
    git = plain_path(root / ".git", directory=True)
    for relative in (
        "commondir",
        "worktrees",
        "reftable",
        "shallow",
        "info/grafts",
        "objects/info/alternates",
        "objects/info/http-alternates",
    ):
        if (git / relative).exists() or (git / relative).is_symlink():
            raise PlanError("unsupported Git metadata indirection")
    records = {}
    for name, directory in (
        ("root", True),
        (".git", True),
        (".git/objects", True),
        (".git/refs", True),
        (".git/config", False),
        (".git/HEAD", False),
    ):
        path = root if name == "root" else root / name
        s = plain_path(path, directory=directory).stat()
        records[name] = {"device": s.st_dev, "inode": s.st_ino}
    for relative, directory in (
        ("objects/info", True),
        ("objects/pack", True),
        ("logs", True),
        ("packed-refs", False),
        ("refs/yamora-gitops", True),
        ("refs/yamora-gitops/targets", True),
    ):
        path = git / relative
        if path.exists() or path.is_symlink():
            s = plain_path(path, directory=directory).stat()
            records[".git/" + relative] = {"device": s.st_dev, "inode": s.st_ino}
    return {"path": str(root), "paths": records, "object_format": object_format}


def _members(group):
    result = []
    for p in Path("/proc").iterdir():
        if not p.name.isdecimal():
            continue
        try:
            fields = (p / "stat").read_bytes().rsplit(b")", 1)[1].split()
        except (FileNotFoundError, ProcessLookupError):
            continue
        if (
            int(fields[2]) == group
            and int(fields[3]) == group
            and fields[0] not in (b"Z", b"X", b"x")
        ):
            result.append(int(p.name))
    return result


class _RetainableWorkspace(tempfile.TemporaryDirectory):
    # Preserve the existing retain-on-uncertain-stop finalizer contract on Python 3.10+.
    _finalizer: weakref.finalize


class _Child:
    """Keep the leader unreaped until group teardown, preventing PID/PGID reuse."""

    def __init__(self, argv, *, cwd, env, end, maximum, retain):
        self.owner_pid, self.owner_thread = os.getpid(), threading.get_ident()
        self.end, self.maximum, self.retain = end, maximum, retain
        self.process = None
        self.launch_admitted = False
        self.selector = selectors.DefaultSelector()
        self.out, self.err = bytearray(), bytearray()
        self.closed = False
        try:
            mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
            try:
                self.launch_admitted = True
                self.process = subprocess.Popen(
                    argv,
                    cwd=cwd,
                    env=env,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    start_new_session=True,
                )
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, mask)
            stdin, stdout, stderr = (
                self.process.stdin,
                self.process.stdout,
                self.process.stderr,
            )
            if stdin is None or stdout is None or stderr is None:
                raise GitInfrastructureError("Git process pipes are unavailable")
            for stream in (stdin, stdout, stderr):
                os.set_blocking(stream.fileno(), False)
            self.selector.register(stdout, selectors.EVENT_READ, self.out)
            self.selector.register(stderr, selectors.EVENT_READ, self.err)
        except BaseException:
            self.close()
            raise

    def _left(self):
        left = self.end - time.monotonic()
        if left <= 0:
            raise GitInfrastructureError("Git command deadline exceeded")
        return left

    def _pump(self, pending=None):
        left = self._left()
        process = self.process
        if process is None:
            raise GitInfrastructureError("owned Git process is unavailable")
        writer = process.stdin
        if pending is not None and len(pending):
            if writer is None:
                raise GitInfrastructureError("Git stdin pipe is unavailable")
            try:
                self.selector.register(writer, selectors.EVENT_WRITE, None)
            except KeyError:
                pass
        amount = 0
        if not self.selector.get_map():
            time.sleep(min(0.01, left))
            return 0
        for key, _ in self.selector.select(min(left, 0.05)):
            if key.fileobj is writer:
                try:
                    amount = os.write(key.fd, pending[:65536])
                except BlockingIOError:
                    continue
                finally:
                    self.selector.unregister(key.fd)
            else:
                try:
                    block = os.read(key.fd, 65536)
                except BlockingIOError:
                    continue
                if not block:
                    self.selector.unregister(key.fileobj)
                    continue
                key.data.extend(block)
                ceiling = self.maximum if key.fileobj is process.stdout else 8192
                if len(key.data) > ceiling:
                    raise GitInfrastructureError("Git pipe output exceeds byte limit")
        return amount

    def send(self, data):
        if not isinstance(data, bytes) or len(data) > 64 * 1024 * 1024:
            raise PlanError("invalid bounded Git stdin")
        pending = memoryview(data)
        while pending:
            amount = self._pump(pending)
            pending = pending[amount:]

    def expect(self, expected):
        process = self.process
        if process is None:
            raise GitInfrastructureError("owned Git process is unavailable")
        while len(self.out) < len(expected):
            if not any(k.fileobj is process.stdout for k in self.selector.get_map().values()):
                raise GitCommandError(self._status() if self._status() is not None else -1)
            self._pump()
        if bytes(self.out[: len(expected)]) != expected:
            raise PlanError("invalid Git transaction acknowledgment")
        del self.out[: len(expected)]

    def eof(self):
        process = self.process
        if process is not None:
            writer = process.stdin
            if writer is not None and not writer.closed:
                writer.close()

    def _status(self):
        # WNOWAIT deliberately retains the leader's PID until our group is stopped.
        process = self.process
        if process is None:
            raise GitInfrastructureError("owned Git process is unavailable")
        state = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        if state is None:
            return None
        return state.si_status if state.si_code == os.CLD_EXITED else -state.si_status

    def finish(self):
        self.eof()
        while self.selector.get_map() or self._status() is None:
            self._pump()
        return self._status(), bytes(self.out)

    def close(self):
        if os.getpid() != self.owner_pid or threading.get_ident() != self.owner_thread:
            self.retain()
            raise GitInfrastructureError("foreign helper owner; no process control")
        if self.closed:
            if self.launch_admitted:
                self.retain()
                raise GitInfrastructureError("owned Git cleanup unverified; retain artifacts")
            return
        try:
            self.closed = True
            mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
        except BaseException as error:
            self.retain()
            raise GitInfrastructureError("cannot protect helper teardown") from error
        try:
            if self.process is None and self.launch_admitted:
                self.selector.close()
                raise GitInfrastructureError("Git launch stop unverified; retain artifacts")
            if self.process is not None:
                self.eof()
                # Do not poll/wait/reap the leader before signaling its owned group.
                for sig, grace in ((signal.SIGTERM, 5.0), (signal.SIGKILL, 5.0)):
                    try:
                        os.killpg(self.process.pid, sig)
                    except ProcessLookupError:
                        pass
                    end = time.monotonic() + grace
                    while _members(self.process.pid) and time.monotonic() < end:
                        time.sleep(0.02)
                if _members(self.process.pid):
                    raise GitInfrastructureError(
                        "owned Git group stop unverified; retain artifacts"
                    )
                self.process.wait(timeout=5)
                for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                    if stream is not None and not stream.closed:
                        stream.close()
            self.selector.close()
            self.launch_admitted = False
        except BaseException as error:
            self.retain()
            if isinstance(error, GitInfrastructureError):
                raise
            raise GitInfrastructureError(
                "owned Git cleanup unverified; retain artifacts"
            ) from error
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)


class GitWriter:
    def __init__(self, repo, limits, end, *, public_policy=None):
        if threading.current_thread() is not threading.main_thread():
            raise PlanError("Git writer requires the main thread for signal ownership")
        self.owner_pid, self.owner_thread = os.getpid(), threading.get_ident()
        self.repo = plain_path(repo, directory=True)
        self.limits, self.end = limits, end
        self.binary = shutil.which("git", path=os.defpath)
        self.ssh_binary = shutil.which("ssh-keygen", path=os.defpath)
        if self.binary is None:
            raise GitInfrastructureError("system Git is unavailable")
        self.workspace = _RetainableWorkspace(dir=os.environ["TMPDIR"], prefix="git-publish-")
        self.work = Path(self.workspace.name)
        self._retained = False
        self.pending_launches = set()
        self.children = set()
        for name in ("home", "config", "tmp"):
            (self.work / name).mkdir(mode=0o700)
        self.policy_file = self.work / "allowed-signers"
        self.policy_file.write_text(public_policy or "", encoding="ascii")
        self.policy_file.chmod(0o600)
        self.revocations = self.work / "revocations"
        self.revocations.touch(mode=0o600)
        self.env = {
            "PATH": os.defpath,
            "LC_ALL": "C",
            "LANG": "C",
            "TZ": "UTC",
            "HOME": str(self.work / "home"),
            "XDG_CONFIG_HOME": str(self.work / "config"),
            "TMPDIR": str(self.work / "tmp"),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_ATTR_NOSYSTEM": "1",
        }

    @property
    def retained(self):
        # Admission stays visible even if interruption skips a cleanup callback.
        return self._retained or bool(self.pending_launches)

    def _retain(self):
        self._retained = True
        # TemporaryDirectory's finalizer must not delete a live helper's workspace.
        self.workspace._finalizer.detach()

    def _owner(self):
        if os.getpid() != self.owner_pid or threading.get_ident() != self.owner_thread:
            self._retain()
            raise GitInfrastructureError("foreign writer owner; no process control")

    def __enter__(self):
        self._owner()
        self.previous_term = signal.signal(signal.SIGTERM, self._cancel)
        return self

    @staticmethod
    def _cancel(signum, frame):
        raise KeyboardInterrupt("Git publication cancelled")

    def __exit__(self, *ignored):
        self._owner()
        try:
            for child in tuple(self.children):
                child.close()
        finally:
            signal.signal(signal.SIGTERM, self.previous_term)
            if not self.retained:
                self.workspace.cleanup()

    @staticmethod
    def _allowed(args):
        def oid(value):
            return isinstance(value, str) and re.fullmatch(OID, value) is not None

        def ref(value):
            return isinstance(value, str) and re.fullmatch(REF, value) is not None

        return (
            args == ["rev-parse", "--show-object-format"]
            or (
                len(args) == 3
                and args[:2] == ["symbolic-ref", "--quiet"]
                and (args[2] == "HEAD" or ref(args[2]))
            )
            or (len(args) == 4 and args[:3] == ["show-ref", "--verify", "--hash"] and ref(args[3]))
            or (
                len(args) == 3
                and args[0] == "cat-file"
                and args[1] in ("commit", "tree", "-s", "blob")
                and oid(args[2])
            )
            or args == ["mktree", "-z"]
            or (
                len(args) == 5
                and args[0] == "hash-object"
                and args[1:3] == ["-w", "-t"]
                and args[3] in ("blob", "tree", "commit")
                and args[4] == "--stdin"
            )
            or (
                len(args) == 5
                and args[0] == "commit-tree"
                and oid(args[1])
                and args[2] == "-p"
                and oid(args[3])
                and args[4] == "-S"
            )
            or (len(args) == 3 and args[:2] == ["verify-commit", "--raw"] and oid(args[2]))
            or args == ["update-ref", "--stdin", "-z"]
        )

    @contextmanager
    def launch(self, args, *, maximum=4096, extra_env=None, private_key=None):
        self._owner()
        if (
            self._retained
            or len(self.pending_launches) != len(self.children)
            or any(child.closed or not child.launch_admitted for child in self.children)
        ):
            raise GitInfrastructureError("unverified prior Git launch; no redispatch")
        if not isinstance(args, list) or not self._allowed(args):
            raise PlanError("unsupported internal Git writer command")
        left = min(self.limits.git_timeout, self.end - time.monotonic())
        if left <= 0:
            raise GitInfrastructureError("Git invocation deadline exceeded")
        config = {
            "core.hooksPath": os.devnull,
            "core.fsmonitor": "false",
            "protocol.allow": "never",
            "maintenance.auto": "false",
            "gc.auto": "0",
            "core.logAllRefUpdates": "false",
            "i18n.commitEncoding": "UTF-8",
            "gpg.format": "ssh",
            "gpg.ssh.program": self.ssh_binary or "/usr/bin/ssh-keygen",
            "gpg.ssh.defaultKeyCommand": "",
            "gpg.ssh.allowedSignersFile": str(self.policy_file),
            "gpg.ssh.revocationFile": str(self.revocations),
        }
        env = dict(self.env)
        if extra_env:
            if args[0] != "commit-tree" or set(extra_env) != {
                "GIT_AUTHOR_NAME",
                "GIT_AUTHOR_EMAIL",
                "GIT_AUTHOR_DATE",
                "GIT_COMMITTER_NAME",
                "GIT_COMMITTER_EMAIL",
                "GIT_COMMITTER_DATE",
            }:
                raise PlanError("unsupported Git identity environment")
            env.update(extra_env)
        if private_key is not None:
            if args[0] != "commit-tree" or not re.fullmatch(r"/proc/[0-9]+/fd/[0-9]+", private_key):
                raise PlanError("invalid signing descriptor")
            config["user.signingKey"] = private_key
        argv = [self.binary, "--no-pager", "--no-replace-objects"]
        for name, value in config.items():
            argv.extend(("-c", name + "=" + value))
        argv.extend(args)
        child = None
        admission = object()
        try:
            # Disable implicit removal before launch can possibly admit a child.
            # Normal verified exit still performs explicit workspace cleanup.
            self.workspace._finalizer.detach()
            self.pending_launches.add(admission)
            child = _Child(
                argv,
                cwd=self.repo,
                env=env,
                end=time.monotonic() + left,
                maximum=maximum,
                retain=self._retain,
            )
            self.children.add(child)
            yield child
        except (OSError, subprocess.SubprocessError) as error:
            raise GitInfrastructureError("bounded Git process failed") from error
        finally:
            if child is None:
                # Construction can fail after OS launch but before handle handoff.
                self._retain()
            else:
                try:
                    child.close()
                finally:
                    if not child.launch_admitted:
                        self.pending_launches.discard(admission)
                    else:
                        self._retain()
                    self.children.discard(child)

    def run(self, args, *, data=b"", maximum=4096, accepted=(0,), extra_env=None, private_key=None):
        with self.launch(
            args, maximum=maximum, extra_env=extra_env, private_key=private_key
        ) as child:
            child.send(data)
            code, output = child.finish()
            if code not in accepted:
                raise GitCommandError(code)
        return code, output
