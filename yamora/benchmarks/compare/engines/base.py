"""Shared engine contract, verification and per-run secrets."""

from __future__ import annotations

import ipaddress
import os
import secrets
import shutil
import stat
from dataclasses import dataclass
from dataclasses import field
from pathlib import Path

from .. import dataset
from .. import podman

CPUS = "2"
MEMORY = "1g"
MEMORY_BYTES = 1024**3
CACHE_BYTES = 256 * 1024**2
TEXT_INDEX = "description"


class VerificationError(AssertionError):
    """An engine answered differently from the deterministic expectation."""


@dataclass
class RunContext:
    """Per-run identity and scratch, shared by every engine of one invocation."""

    run_id: str
    work_root: Path
    network: str = ""
    subnet: str = ""
    secrets: list = field(default_factory=list)

    def private_address(self, offset: int) -> str:
        """A fixed RFC 1918 host address in this run's private Podman network."""
        network = ipaddress.ip_network(self.subnet)
        if not network.is_private or network.version != 4 or network.num_addresses < 256:
            raise podman.PodmanError("benchmark network must be a private IPv4 /24 or larger")
        return str(network.network_address + 10 + offset)

    def directory(self, *parts: str) -> Path:
        path = self.work_root.joinpath(*parts)
        path.mkdir(mode=0o700, parents=True, exist_ok=False)
        return path

    def write_secret(self, directory: Path, name: str, value: str | None = None) -> Path:
        """Create one 0600 secret file; the value is remembered only to prove
        that results never contain it."""
        value = value or secrets.token_urlsafe(32)
        path = directory / name
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "w") as handle:
            handle.write(value + "\n")
        self.secrets.append(value)
        return path


def remove_tree(path: Path, root: Path) -> None:
    """Delete one directory this run created, never a path outside its root."""
    resolved_root = root.resolve()
    if path.is_symlink():
        raise podman.PodmanError("refusing to remove a symbolic link")
    resolved = path.resolve()
    if resolved == resolved_root or resolved_root not in resolved.parents:
        raise podman.PodmanError("refusing to remove a path outside the run directory")
    if not stat.S_ISDIR(os.lstat(resolved).st_mode):
        raise podman.PodmanError("refusing to remove a non-directory")
    try:
        shutil.rmtree(resolved)
    except PermissionError:
        # A container runtime can leave entries owned by a subordinate UID
        # (for example a mount point it had to create). Only the rootless user
        # namespace that mapped them can delete them.
        podman.run(["unshare", "rm", "-rf", "--one-file-system", "--", str(resolved)], timeout=300)
        if os.path.lexists(resolved):
            raise


def directory_usage(path: Path) -> dict:
    """Allocated (st_blocks) and apparent bytes, with a top-level breakdown."""
    total_allocated = total_apparent = files = 0
    breakdown: dict[str, int] = {}
    for current, directories, names in os.walk(path, followlinks=False):
        directories[:] = [
            item for item in directories if not os.path.islink(os.path.join(current, item))
        ]
        for name in names:
            full = os.path.join(current, name)
            try:
                info = os.lstat(full)
            except OSError:
                continue
            if not stat.S_ISREG(info.st_mode):
                continue
            allocated = info.st_blocks * 512
            files += 1
            total_allocated += allocated
            total_apparent += info.st_size
            # Group by up to three directory levels, so PostgreSQL's
            # 18/docker/base/ and 18/docker/pg_wal/ stay distinguishable.
            relative = os.path.relpath(full, path).split(os.sep)
            parents = relative[:-1][:3]
            key = "/".join(parents) + "/" if parents else relative[0]
            breakdown[key] = breakdown.get(key, 0) + allocated
    largest = dict(sorted(breakdown.items(), key=lambda item: (-item[1], item[0]))[:12])
    return {
        "allocated_bytes": total_allocated,
        "apparent_bytes": total_apparent,
        "files": files,
        "largest_entries_allocated_bytes": largest,
    }


# Verification ---------------------------------------------------------------


def verify_rows(operation: tuple, rows: list, expectations: dataset.Expectations) -> None:
    """Check returned ``(id, fields)`` rows against the generator's answers."""
    expected = expectations.expected_rows(operation)
    if len(rows) != expected:
        raise VerificationError(f"{operation[0]} returned {len(rows)} rows, expected {expected}")
    kind = operation[0]
    previous = None
    for document_id, fields in rows:
        if kind == "get" and isinstance(fields, bytes):
            # Raw source reads must return the stored YAML byte for byte.
            index = int(document_id.removeprefix("doc-"))
            stored = dataset.to_yaml(document_id, dataset.document_fields(expectations.seed, index))
            if fields != stored.encode("utf-8"):
                raise VerificationError("raw read did not return the exact stored YAML")
            continue
        if not isinstance(fields, dict):
            raise VerificationError(f"{kind} returned a non-map document")
        if kind == "eq" and fields.get("category") != operation[1]:
            raise VerificationError("equality query returned a non-matching document")
        if kind == "range":
            price = fields.get("price")
            if not (isinstance(price, int) and operation[1] <= price < operation[2]):
                raise VerificationError("range query returned a price outside the range")
            if previous is not None and price < previous:
                raise VerificationError("range query results are not sorted by price")
            previous = price
        if kind == "text" and operation[1] not in fields.get("description", "").split():
            raise VerificationError("text search returned a document without the term")
        if kind == "get":
            index = int(document_id.removeprefix("doc-"))
            if fields != dataset.document_fields(expectations.seed, index):
                raise VerificationError("point read returned different values")


def verify_aggregate(rows: list, expectations: dataset.Expectations) -> None:
    expected = expectations.aggregate_rows()
    if len(rows) != len(expected):
        raise VerificationError("aggregation returned a different number of groups")
    for actual, wanted in zip(rows, expected, strict=True):
        if actual["_id"] != wanted["_id"] or actual["count"] != wanted["count"]:
            raise VerificationError(f"aggregation group {wanted['_id']} differs")
        if abs(float(actual["avg_price"]) - wanted["avg_price"]) > 1e-6 * max(
            1, wanted["avg_price"]
        ):
            raise VerificationError(f"aggregation average for {wanted['_id']} differs")


class Server:
    """Server lifecycle on the host; subclasses define one engine."""

    engine = ""
    container_port = 0

    def __init__(self, context: RunContext, repetition: int):
        self.context = context
        self.repetition = repetition
        self.name = f"ycb-{context.run_id[:12]}-{self.engine}-r{repetition}"
        self.container = podman.Container(self.name, context.run_id, self.engine)
        self.root = context.directory(f"{self.engine}-r{repetition}")
        self.data_dir = self.root / "data"
        self.data_dir.mkdir(mode=0o700)
        self.secret_dir = self.root / "secrets"
        self.secret_dir.mkdir(mode=0o700)
        self.port = 0

    def teardown(self) -> dict:
        self.container.remove()
        left = [name for name in podman.remaining(self.context.run_id) if name == self.name]
        removed = False
        if self.root.exists():
            remove_tree(self.root, self.context.work_root)
            removed = not self.root.exists()
        return {"container_removed": not left, "data_removed": removed}
