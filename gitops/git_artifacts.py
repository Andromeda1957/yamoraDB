"""Private immutable publication artifacts and a durable one-shot dispatch fence."""

from __future__ import annotations

import fcntl
import os
import secrets
import stat
from contextlib import contextmanager

from .git_reader import plain_path
from .model import PlanError
from .model import canonical
from .model import strict_json
from .validation import sha256

MAX_ARTIFACT = 256 * 1024 * 1024
NAMES = frozenset(("intent.json", "staged.json", "attempt.json", "receipt.json"))


class ArtifactBusy(PlanError):
    """Another publication owns this intent's advisory lock."""


def identity(fd):
    s = os.fstat(fd)
    return (s.st_dev, s.st_ino)


def private(fd, *, directory=False):
    s = os.fstat(fd)
    kind = stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode)
    mode = 0o700 if directory else 0o600
    if not kind or s.st_uid != os.getuid() or stat.S_IMODE(s.st_mode) != mode:
        raise PlanError("artifact must be private and owned by the current user")
    if not directory and s.st_nlink != 1:
        raise PlanError("artifact hardlinks are unsupported")


class GitArtifacts:
    def __init__(self, root):
        self.root = plain_path(root, directory=True)
        self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            private(self.fd, directory=True)
            self.root_identity = identity(self.fd)
            self.revalidate()
        except BaseException:
            os.close(self.fd)
            self.fd = -1
            raise

    def close(self):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self):
        self.revalidate()
        return self

    def __exit__(self, *ignored):
        self.close()

    def revalidate(self):
        path = plain_path(self.root, directory=True)
        s = path.stat()
        if self.fd < 0 or (s.st_dev, s.st_ino) != self.root_identity:
            raise PlanError("artifact root identity changed")
        private(self.fd, directory=True)
        if identity(self.fd) != self.root_identity:
            raise PlanError("artifact descriptor identity changed")

    def outside(self, repo):
        self.revalidate()
        if self.root == repo or self.root in repo.parents or repo in self.root.parents:
            raise PlanError("artifact and repository roots must be disjoint")

    @contextmanager
    def directory(self, intent_id, *, create=False):
        sha256(intent_id)
        self.revalidate()
        if create:
            try:
                os.mkdir(intent_id, 0o700, dir_fd=self.fd)
            except FileExistsError:
                pass
        fd = os.open(
            intent_id, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.fd
        )
        try:
            private(fd, directory=True)
            s = os.stat(intent_id, dir_fd=self.fd, follow_symlinks=False)
            if (s.st_dev, s.st_ino) != identity(fd):
                raise PlanError("intent directory identity changed")
            if create:
                os.fsync(fd)
                os.fsync(self.fd)  # NEW_INTENT_PARENT_BARRIER
            yield fd
            self.revalidate()
            s = os.stat(intent_id, dir_fd=self.fd, follow_symlinks=False)
            if (s.st_dev, s.st_ino) != identity(fd):
                raise PlanError("intent directory identity changed")
        finally:
            os.close(fd)

    def binding(self, intent_id):
        with self.directory(intent_id) as fd:
            child = os.fstat(fd)
            return {
                "path": str(self.root),
                "device": self.root_identity[0],
                "inode": self.root_identity[1],
                "intent_device": child.st_dev,
                "intent_inode": child.st_ino,
            }

    @staticmethod
    def _read(fd, name, maximum):
        file_fd = os.open(
            name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd
        )
        try:
            private(file_fd)
            if os.fstat(file_fd).st_size > maximum:
                raise PlanError("artifact exceeds byte limit")
            with os.fdopen(os.dup(file_fd), "rb") as stream:
                data = stream.read(maximum + 1)
            if len(data) > maximum:
                raise PlanError("artifact exceeds byte limit")
            s = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if (s.st_dev, s.st_ino) != identity(file_fd):
                raise PlanError("artifact identity changed while reading")
            return data, file_fd
        except BaseException:
            os.close(file_fd)
            raise

    def read(self, intent_id, name, *, maximum=MAX_ARTIFACT):
        if name not in NAMES or type(maximum) is not int or not 0 < maximum <= MAX_ARTIFACT:
            raise PlanError("unsupported artifact read")
        with self.directory(intent_id) as fd:
            data, file_fd = self._read(fd, name, maximum)
            os.close(file_fd)
        value = strict_json(data)
        if canonical(value) + b"\n" != data:
            raise PlanError("noncanonical stored artifact")
        return value

    def exists(self, intent_id, name):
        if name not in NAMES:
            raise PlanError("unsupported artifact name")
        with self.directory(intent_id) as fd:
            try:
                os.stat(name, dir_fd=fd, follow_symlinks=False)
                return True
            except FileNotFoundError:
                return False

    def put(self, intent_id, name, value, *, allow_existing=True):
        if name not in NAMES or type(allow_existing) is not bool:
            raise PlanError("unsupported artifact write")
        data = canonical(value) + b"\n"
        if len(data) > MAX_ARTIFACT:
            raise PlanError("artifact exceeds byte limit")
        # Validate exactly what will be persisted, including JSON value restrictions.
        strict_json(data)
        if name == "attempt.json":
            if allow_existing:
                raise PlanError("attempt marker requires exclusive creation")
            with self.directory(intent_id, create=True) as fd:
                try:
                    marker = os.open(
                        name,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                        0o600,
                        dir_fd=fd,
                    )
                except FileExistsError:
                    raise PlanError("publication attempt already fenced") from None
                try:
                    offset = 0
                    while offset < len(data):
                        amount = os.write(marker, data[offset:])
                        if amount <= 0:
                            raise OSError("short attempt marker write")
                        offset += amount
                    os.fsync(marker)
                    os.fsync(fd)
                finally:
                    os.close(marker)
                # Never unlink an empty or partial positive admission marker.
            return
        with self.directory(intent_id, create=True) as fd:
            temporary = "." + name + "." + secrets.token_hex(16)
            output = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=fd,
            )
            own = identity(output)
            try:
                try:
                    cursor = 0
                    while cursor < len(data):
                        amount = os.write(output, data[cursor:])
                        if amount <= 0:
                            raise OSError("short artifact write")
                        cursor += amount
                    os.fsync(output)
                finally:
                    os.close(output)
                try:
                    os.link(temporary, name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
                except FileExistsError:
                    if not allow_existing:
                        raise PlanError("publication attempt already fenced") from None
                    existing, old_fd = self._read(fd, name, MAX_ARTIFACT)
                    try:
                        if existing != data:
                            raise PlanError("immutable artifact differs")
                        os.fsync(old_fd)
                    finally:
                        os.close(old_fd)
                os.fsync(fd)
            finally:
                # Only remove the exact temporary inode created by this call.
                try:
                    s = os.stat(temporary, dir_fd=fd, follow_symlinks=False)
                    if (s.st_dev, s.st_ino) == own:
                        os.unlink(temporary, dir_fd=fd)
                        os.fsync(fd)
                except FileNotFoundError:
                    pass

    def prepare_lock(self, intent_id):
        with self.directory(intent_id, create=True) as fd:
            try:
                lock = os.open(
                    "publish.lock",
                    os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600,
                    dir_fd=fd,
                )
            except FileExistsError:
                lock = os.open("publish.lock", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            try:
                private(lock)
                if os.fstat(lock).st_size:
                    raise PlanError("invalid intent lock")
                os.fsync(lock)
                os.fsync(fd)
            finally:
                os.close(lock)

    @contextmanager
    def hold(self, intent_id, *, exclusive):
        with self.directory(intent_id) as fd:
            lock = os.open("publish.lock", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            try:
                private(lock)
                if os.fstat(lock).st_size:
                    raise PlanError("invalid intent lock")
                try:
                    fcntl.flock(
                        lock, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB
                    )
                except BlockingIOError:
                    raise ArtifactBusy("publication is in progress") from None
                yield
            finally:
                os.close(lock)
