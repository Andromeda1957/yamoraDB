"""YamoraDB built from this checkout, run as the same binary inside Podman.

The daemon is compiled from the working tree with the Makefile's own flags.
Its exact host shared libraries (from ``ldd``) are copied into a minimal root
filesystem, so Podman applies the same ``--cpus``/``--memory`` cgroup limits,
network path and bind-mounted filesystem as the two image-based engines,
without rebuilding the binary against another distribution.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import time
from pathlib import Path

import tomllib

from .. import dataset
from .. import podman
from ..commands import CommandError
from ..commands import run_fixed
from .base import CACHE_BYTES
from .base import CPUS
from .base import MEMORY
from .base import TEXT_INDEX
from .base import RunContext
from .base import Server

YAMORA_DIR = Path(__file__).resolve().parents[3]
CONTAINER_PORT = 8765
DURABILITY = (
    "Native disk engine default (not configurable): each commit writes its records and "
    "copy-on-write tree pages, synchronizes, writes the alternate superblock and "
    "synchronizes again before replying."
)
CLIENT = (
    "yamora.YamoraClient (Python standard library, HTTP/1.1 JSON, new TCP connection per request)"
)


def package_version() -> str:
    with open(YAMORA_DIR / "pyproject.toml", "rb") as handle:
        return tomllib.load(handle)["project"]["version"]


def _sha256(path: Path) -> str:
    with open(path, "rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def build(work_root: Path, binary: str | None = None) -> dict:
    """Compile the daemon from this tree into scratch, or describe a given one."""
    compiler = os.environ.get("CC", "cc")
    if binary is None:
        build_dir = work_root / "build"
        target = build_dir / "yamora"
        completed = run_fixed(
            ["make", "-C", str(YAMORA_DIR), f"BUILD_DIR={build_dir}", str(target)], timeout=3600
        )
        if completed.returncode != 0:
            tail = "\n".join(completed.stderr.strip().splitlines()[-10:])
            raise podman.PodmanError(f"yamora build failed:\n{tail}")
        source = "built from this checkout with the Makefile defaults"
    else:
        target = Path(binary).resolve()
        if not target.is_file() or not os.access(target, os.X_OK):
            raise podman.PodmanError("--yamora-binary must be an executable file")
        source = "supplied with --yamora-binary"
    try:
        version = run_fixed([compiler, "--version"], timeout=60).stdout.splitlines()
    except CommandError:
        version = []  # an unusual CC name is recorded as given, without running it
    return {
        "binary": str(target),
        "source": source,
        "sha256": _sha256(target),
        "bytes": target.stat().st_size,
        "compiler": version[0] if version else compiler,
        "make_command": "make -C yamora BUILD_DIR=<scratch>/build <scratch>/build/yamora"
        if binary is None
        else None,
    }


def shared_libraries(binary: Path) -> list:
    """(path seen by the loader, host file) pairs from ``ldd``."""
    completed = run_fixed(["ldd", str(binary)], timeout=60)
    if completed.returncode != 0:
        raise podman.PodmanError("ldd could not list the yamora binary's libraries")
    pairs = []
    for line in completed.stdout.splitlines():
        text = line.strip()
        if "=>" in text:
            name, _, rest = text.partition("=>")
            target = rest.strip().split(" (", 1)[0].strip()
            if not target.startswith("/"):
                continue  # vDSO or unresolved; the loader would fail anyway
            pairs.append((target, target))
            if name.strip().startswith("/"):
                pairs.append((name.strip(), target))
        elif text.startswith("/"):
            path = text.split(" (", 1)[0]
            pairs.append((path, path))
    if not pairs:
        raise podman.PodmanError("ldd found no shared libraries for the yamora binary")
    return pairs


def make_rootfs(binary: Path, root: Path) -> dict:
    """A root filesystem holding only the daemon and its loader dependencies."""
    root.mkdir(mode=0o700)
    # Every mount point the runtime needs exists in advance and belongs to the
    # invoking user; one it creates itself (``/run`` in the first smoke run)
    # belongs to a subordinate UID and could not be deleted afterwards.
    for mount_point in ("data", "secrets", "tmp", "etc", "dev", "proc", "sys", "run"):
        (root / mount_point).mkdir(mode=0o755)
    shutil.copy2(binary, root / "yamora")
    copied = []
    for seen, host in shared_libraries(binary):
        destination = root / seen.lstrip("/")
        destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        if not destination.exists():
            shutil.copy2(Path(host).resolve(), destination)
            copied.append(seen)
    return {"libraries": sorted(copied)}


class YamoraServer(Server):
    engine = "yamora"
    container_port = CONTAINER_PORT

    def __init__(self, context: RunContext, repetition: int, *, rootfs: Path, build_info: dict):
        super().__init__(context, repetition)
        self.rootfs = rootfs
        self.build_info = build_info
        self.read_token = context.write_secret(self.secret_dir, "read.token")
        self.write_token = context.write_secret(self.secret_dir, "write.token")
        self.address = context.private_address(repetition)
        self.command = [
            "/yamora",
            "--data-dir",
            "/data",
            "--bind-address",
            self.address,
            "--port",
            str(CONTAINER_PORT),
            "--cache-bytes",
            str(CACHE_BYTES),
            "--auth-token-file",
            "/secrets/read.token",
            "--write-auth-token-file",
            "/secrets/write.token",
        ]

    def start(self) -> None:
        podman.run_once(
            run_label=self.context.run_id,
            engine=self.engine,
            name=f"{self.name}-init",
            image_or_rootfs=["--rootfs", str(self.rootfs)],
            mounts=[(str(self.data_dir), "/data", "rw")],
            userns="keep-id",
            command=["/yamora", "--data-dir", "/data", "--init-disk", "--validate-only"],
        )
        self.container.start(
            image_or_rootfs=["--rootfs", str(self.rootfs)],
            mounts=[(str(self.data_dir), "/data", "rw"), (str(self.secret_dir), "/secrets", "ro")],
            environment={},
            container_port=CONTAINER_PORT,
            cpus=CPUS,
            memory=MEMORY,
            userns="keep-id",
            command=self.command,
            network=self.context.network,
            address=self.address,
        )
        self.port = self.container.host_port(CONTAINER_PORT)
        deadline = time.monotonic() + 120
        while True:
            try:
                client = YamoraBenchClient(self.spec())
                client.db.ready()
                return
            except Exception:
                if time.monotonic() > deadline or not self.container.running():
                    raise
                time.sleep(0.25)

    def spec(self) -> dict:
        return {
            "engine": self.engine,
            "port": self.port,
            "read_token_file": str(self.read_token),
            "write_token_file": str(self.write_token),
        }

    def describe(self, client) -> dict:
        stats = client.db.stats()
        build = dict(self.build_info)
        if build.get("make_command"):
            # The scratch volume path is host-specific and removed after the run.
            build["binary"] = "<scratch>/build/yamora"
        return {
            "product": "YamoraDB",
            "version": f"{package_version()} (Python package version; daemon from this checkout)",
            "build": build,
            "runtime": "podman --rootfs: the built binary plus its host shared libraries",
            "server_command": self.command,
            "storage": {
                key: stats.get(key) for key in ("storage", "backend", "format") if key in stats
            },
            "durability": DURABILITY,
            "cache": f"--cache-bytes {CACHE_BYTES} (tree pages only; records use the OS page cache)",
            "client": CLIENT,
        }

    def setup(self, client) -> None:
        client.db.create_index(dataset.COLLECTION, "category", ["category"])
        client.db.create_index(dataset.COLLECTION, "price", ["price"])
        client.db.create_text_index(dataset.COLLECTION, TEXT_INDEX, ["description"])

    def after_ingest(self, client) -> None:
        """No statistics or maintenance step exists; every commit is durable."""

    def checkpoint(self, client) -> None:
        """Every acknowledged commit is already synchronized; nothing to flush."""


class YamoraBenchClient:
    name = CLIENT

    def __init__(self, spec: dict):
        from yamora import YamoraClient

        self.db = YamoraClient(
            host="127.0.0.1",
            port=spec["port"],
            timeout=30,
            auth_token_file=spec["read_token_file"],
            write_auth_token_file=spec["write_token_file"],
        )

    def close(self) -> None:
        """Each request already closed its own connection."""

    @staticmethod
    def prepare_insert(documents: list) -> list:
        return [
            {
                "collection": dataset.COLLECTION,
                "document": item.id,
                "put": dataset.to_yaml(item.id, item.fields),
                "create_only": True,
            }
            for item in documents
        ]

    def insert(self, payload: list) -> int:
        self.db.transaction(payload)
        return len(payload)

    def delete(self, identifiers: list) -> int:
        self.db.transaction(
            [
                {"collection": dataset.COLLECTION, "document": item, "delete": True}
                for item in identifiers
            ]
        )
        return len(identifiers)

    @staticmethod
    def _spec(operation: tuple) -> dict:
        if operation[0] == "eq":
            return {
                "filter": {"category": operation[1]},
                "limit": dataset.QUERY_LIMIT,
                "include_count": False,
            }
        return {
            "filter": {"price": {"$gte": operation[1], "$lt": operation[2]}},
            "sort": {"price": "asc"},
            "limit": dataset.QUERY_LIMIT,
            "include_count": False,
        }

    def run(self, operation: tuple) -> int:
        kind = operation[0]
        if kind == "get":
            return 1 if self.db.get(dataset.COLLECTION, operation[1]) else 0
        if kind in ("eq", "range"):
            return len(self.db.query(dataset.COLLECTION, self._spec(operation))["documents"])
        if kind == "text":
            return len(self._search(operation[1])["documents"])
        if kind == "update":
            self.db.patch(dataset.COLLECTION, operation[1], {"$inc": {"stock": 1}})
            return 1
        if kind == "aggregate":
            return len(self.aggregate())
        raise ValueError(f"unknown operation {kind}")

    def _search(self, term: str) -> dict:
        return self.db.search(
            dataset.COLLECTION, TEXT_INDEX, term, mode="all", limit=dataset.QUERY_LIMIT
        )

    def fetch(self, operation: tuple) -> list:
        kind = operation[0]
        if kind == "get":
            # Exact bytes: verification compares them with the YAML that was
            # stored, comment and formatting included.
            return [(operation[1], self.db.get(dataset.COLLECTION, operation[1]))]
        if kind in ("eq", "range"):
            rows = self.db.query(dataset.COLLECTION, self._spec(operation))["documents"]
        else:
            rows = self._search(operation[1])["documents"]
        return [(row["id"], row["value"]) for row in rows]

    def raw(self, document_id: str) -> bytes:
        return self.db.get(dataset.COLLECTION, document_id)

    def aggregate(self) -> list:
        result = self.db.aggregate(
            dataset.COLLECTION,
            [
                {
                    "$group": {
                        "_id": "$category",
                        "count": {"$sum": 1},
                        "avg_price": {"$avg": "$price"},
                    }
                },
                {"$sort": {"_id": 1}},
            ],
        )
        return result["documents"]

    def stock_sum(self) -> int:
        result = self.db.aggregate(
            dataset.COLLECTION, [{"$group": {"_id": None, "stock": {"$sum": "$stock"}}}]
        )
        return int(result["documents"][0]["stock"])

    def count(self) -> int:
        return self.db.count(dataset.COLLECTION)

    def plans(self, operations: dict) -> dict:
        plans = {}
        for name in ("eq", "range"):
            plans[name] = self.db.explain(dataset.COLLECTION, self._spec(operations[name]))
        result = self._search(operations["text"][1])
        plans["text"] = {
            "method": "native inverted postings (search API reports work counters)",
            "documents_examined": result.get("documents_examined"),
            "index_entries_examined": result.get("index_entries_examined"),
        }
        return plans
