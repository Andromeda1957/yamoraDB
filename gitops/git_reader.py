"""Read committed blobs only, using restricted argv and bounded Git processes."""

from __future__ import annotations

import os
import re
import selectors
import shutil
import signal
import stat
import subprocess
import time
from pathlib import Path

from .model import PlanError
from .model import identifier


def plain_path(path, *, directory):
    """Reject symlinks in every existing path component, including the leaf."""
    path = Path(os.path.abspath(path))
    for part in (*reversed(path.parents), path):
        metadata = part.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise PlanError("symlink in input path")
    mode = path.stat().st_mode
    if not (stat.S_ISDIR(mode) if directory else stat.S_ISREG(mode)):
        raise PlanError("input must be a regular file or directory")
    return path


class GitReader:
    def __init__(self, repo, limits, *, _deadline=None):
        self.repo = plain_path(repo, directory=True)
        # Non-bare repositories only. Git worktree indirection is intentionally
        # unsupported: untrusted .git files must not select another object root.
        plain_path(self.repo / ".git", directory=True)
        self.limits = limits
        self.deadline = _deadline if _deadline is not None else time.monotonic() + limits.deadline
        self.binary = shutil.which("git", path=os.defpath)
        if self.binary is None:
            raise PlanError("system Git is unavailable")

    def _run(self, args, maximum, data=None):
        # This private runner cannot be reused for a Git mutation or transport.
        # Only the batch blob reader takes input: newline-terminated object IDs.
        oid = r"(?:[0-9a-f]{40}|[0-9a-f]{64})"
        selector_pattern = (
            r"(?:HEAD|" + oid + r"|refs/(?:heads|tags)/[A-Za-z0-9][A-Za-z0-9/_-]{0,220})"
        )
        allowed = (
            (
                len(args) == 4
                and args[:3] == ["rev-parse", "--verify", "--end-of-options"]
                and re.fullmatch(selector_pattern + r"\^\{(?:commit|tree)\}", args[3]) is not None
            )
            or (
                len(args) == 7
                and args[:6] == ["ls-tree", "-r", "-t", "-l", "-z", "--full-tree"]
                and re.fullmatch(oid, args[6]) is not None
            )
            or (
                args == ["cat-file", "--batch"]
                and isinstance(data, bytes)
                and re.fullmatch(rb"(?:(?:[0-9a-f]{40}|[0-9a-f]{64})\n)+", data) is not None
            )
        )
        if not allowed or (data is not None and args[0] != "cat-file"):
            raise PlanError("unsupported internal Git read command")
        remaining = min(self.limits.git_timeout, self.deadline - time.monotonic())
        if remaining <= 0:
            raise PlanError("Git planning deadline exceeded")
        env = {
            "PATH": os.defpath,
            "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_ATTR_NOSYSTEM": "1",
        }
        if "TMPDIR" in os.environ:
            env["TMPDIR"] = os.environ["TMPDIR"]
        argv = [
            self.binary,
            "--no-pager",
            "--no-replace-objects",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "protocol.allow=never",
            "-c",
            "maintenance.auto=false",
            "-c",
            "gc.auto=0",
            *args,
        ]
        end = time.monotonic() + remaining
        process = None
        try:
            # Defer Ctrl-C through constructor return and handle publication.
            # The child inherits the mask; cleanup always uses SIGKILL.
            previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT})
            try:
                process = subprocess.Popen(
                    argv,
                    cwd=self.repo,
                    env=env,
                    stdin=subprocess.DEVNULL if data is None else subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
            stdout, stderr = process.stdout, process.stderr
            if stdout is None or stderr is None or (data is not None and process.stdin is None):
                raise PlanError("Git output pipes are unavailable")
            stdout_fd = stdout.fileno()
            output = {stdout_fd: bytearray(), stderr.fileno(): bytearray()}
            pending = memoryview(data or b"")
            try:
                with selectors.DefaultSelector() as selector:
                    for descriptor in output:
                        os.set_blocking(descriptor, False)
                        selector.register(descriptor, selectors.EVENT_READ)
                    stdin_fd = None
                    if process.stdin is not None:
                        # Feed input while draining output, so neither pipe can
                        # fill and stall the child.
                        stdin_fd = process.stdin.fileno()
                        os.set_blocking(stdin_fd, False)
                        selector.register(stdin_fd, selectors.EVENT_WRITE)
                    while selector.get_map():
                        left = end - time.monotonic()
                        if left <= 0:
                            raise PlanError("Git command deadline exceeded")
                        for key, _ in selector.select(left):
                            if key.fd == stdin_fd and process.stdin is not None:
                                try:
                                    pending = pending[os.write(key.fd, pending[:65536]) :]
                                except BrokenPipeError:
                                    pending = pending[:0]
                                if not pending:
                                    selector.unregister(key.fd)
                                    process.stdin.close()
                                continue
                            block = os.read(key.fd, 65536)
                            if not block:
                                selector.unregister(key.fd)
                                continue
                            target = output[key.fd]
                            target.extend(block)
                            if len(target) > (maximum if key.fd == stdout_fd else 8192):
                                raise PlanError("Git command output exceeds limit")
                process.wait(timeout=max(0.001, end - time.monotonic()))
                if process.returncode:
                    # Do not expose untrusted config, paths, or helper output.
                    raise PlanError("Git read failed; object must be available locally")
                return bytes(output[stdout_fd])
            except subprocess.TimeoutExpired as exc:
                raise PlanError("Git command deadline exceeded") from exc
        finally:
            if process is not None:
                # Repeated Ctrl-C cannot interrupt reaping and pipe closure.
                previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT})
                try:
                    if process.poll() is None:
                        process.kill()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired as exc:
                        raise PlanError(
                            "owned Git process stop unverified; retain scratch"
                        ) from exc
                    for stream in (process.stdin, process.stdout, process.stderr):
                        if stream is not None:
                            stream.close()
                finally:
                    signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)

    def resolve(self, selector, kind):
        if (
            not isinstance(selector, str)
            or len(selector) > 256
            or not (
                re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", selector)
                or selector == "HEAD"
                or re.fullmatch(r"refs/(heads|tags)/[A-Za-z0-9][A-Za-z0-9/_-]{0,220}", selector)
            )
        ):
            raise PlanError("Git selector must be HEAD, full OID, or a plain heads/tags ref")
        if kind not in ("commit", "tree"):
            raise PlanError("unsupported Git object kind")
        result = self._run(
            ["rev-parse", "--verify", "--end-of-options", selector + "^{" + kind + "}"], 130
        )
        oid = result.decode("ascii").strip()
        if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", oid) is None:
            raise PlanError("Git returned an invalid object ID")
        return oid

    def documents(self, tree, mappings):
        return self.snapshot(tree, mappings)[0]

    def snapshot(self, tree, mappings):
        """Return mapped documents and each present mapping-prefix tree OID.

        Both come from one listing, which also gives every blob size, so all
        limits hold before one batch process reads every mapped blob. Process
        count stays constant at any collection size. A prefix tree may be
        empty: Git can record an empty collection that ordinary checkouts cannot.
        """
        listing = self._run(
            ["ls-tree", "-r", "-t", "-l", "-z", "--full-tree", tree],
            min(self.limits.max_tree_entries * 512, 64 * 1024 * 1024),
        )
        rows = listing.split(b"\0")
        if rows[-1] != b"" or len(rows) - 1 > self.limits.max_tree_entries:
            raise PlanError("Git tree exceeds entry limit or is malformed")
        wanted: list[tuple[tuple[str, str], str, int]] = []
        trees: dict[str, str] = {}
        total = 0
        for row in rows[:-1]:
            if time.monotonic() >= self.deadline:
                raise PlanError("Git planning deadline exceeded")
            metadata, separator, raw_path = row.partition(b"\t")
            fields = metadata.decode("ascii").split()
            if not separator or len(fields) != 4:
                raise PlanError("malformed Git tree listing")
            mode, kind, oid, length = fields
            for mapping in mappings:
                prefix = mapping.prefix.encode("ascii")
                ancestor = raw_path == prefix or prefix.startswith(raw_path + b"/")
                mapped = raw_path.startswith(prefix + b"/")
                if ancestor and (mode != "040000" or kind != "tree"):
                    raise PlanError("Git mapping ancestor is not a directory")
                if raw_path == prefix:
                    if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", oid) is None:
                        raise PlanError("invalid Git tree ID")
                    trees[mapping.collection] = oid
                if not mapped:
                    continue
                if mode != "100644" or kind != "blob":
                    raise PlanError("mapped Git entry must be a regular non-executable blob")
                name = raw_path[len(prefix) + 1 :]
                if not name.endswith(b".yaml"):
                    raise PlanError("mapped Git directory must contain only document.yaml blobs")
                try:
                    document = identifier(name[:-5].decode("ascii"))
                except UnicodeError as exc:
                    raise PlanError("invalid mapped Git document name") from exc
                if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", oid) is None:
                    raise PlanError("invalid Git blob ID")
                if len(wanted) >= self.limits.max_documents:
                    raise PlanError("Git document count exceeds limit")
                if re.fullmatch(r"0|[1-9][0-9]{0,19}", length) is None:
                    raise PlanError("invalid Git blob size")
                # Check sizes before allocating/reading any potentially huge blob.
                size = int(length)
                total += size
                if size > self.limits.max_document_bytes or total > self.limits.max_total_bytes:
                    raise PlanError("Git source bytes exceed limit")
                wanted.append(((mapping.collection, document), oid, size))
        documents: dict[tuple[str, str], tuple[bytes, str]] = {}
        if not wanted:
            return documents, trees
        output = self._run(
            ["cat-file", "--batch"],
            total + len(wanted) * 96,
            data=b"".join(oid.encode("ascii") + b"\n" for _, oid, _ in wanted),
        )
        view, offset = memoryview(output), 0
        for key, oid, size in wanted:
            header = f"{oid} blob {size}\n".encode("ascii")
            start = offset + len(header)
            if view[offset:start] != header or view[start + size : start + size + 1] != b"\n":
                raise PlanError("Git blob batch differs from the listed tree")
            documents[key] = (bytes(view[start : start + size]), oid)
            offset = start + size + 1
        if offset != len(output):
            raise PlanError("Git blob batch differs from the listed tree")
        return documents, trees
