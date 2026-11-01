"""MongoDB Community from the official image, pinned by digest."""

from __future__ import annotations

import time

from .. import dataset
from ..mongo_wire import MongoConnection
from .base import CPUS
from .base import MEMORY
from .base import RunContext
from .base import Server

IMAGE = "docker.io/library/mongo@sha256:452bdaf2127b8ff851e31410a267809b9829eded219979f2210e7c7efb85a058"
TAG = "9.0.4"
PLATFORM_MANIFEST = "sha256:ce91889f87a369d312e50ecbc6c0b7f960e915bc4b69c4f6662402fa7011d242"
CONTAINER_PORT = 27017
DATABASE = "bench"
USER = "bench"
WRITE_CONCERN = {"w": 1, "j": True}
CACHE_GB = "0.25"
SECRET_MOUNT = "/run/benchmark-secrets"
DURABILITY = (
    "WiredTiger journal on (always enabled since MongoDB 6.1); every insert, update and "
    "delete uses writeConcern {w: 1, j: true}, which waits for the journal flush."
)
CLIENT = (
    "yamora.benchmarks.compare.mongo_wire (Python standard library OP_MSG/BSON/SCRAM-SHA-256; "
    "one persistent TCP connection per client process; not the official driver)"
)


class MongoServer(Server):
    engine = "mongodb"
    container_port = CONTAINER_PORT

    def __init__(self, context: RunContext, repetition: int):
        super().__init__(context, repetition)
        password_file = context.write_secret(self.secret_dir, "mongodb-password")
        self._password = password_file.read_text().strip()
        self.command = ["mongod", "--wiredTigerCacheSizeGB", CACHE_GB, "--bind_ip_all"]

    def start(self) -> None:
        self.container.start(
            image_or_rootfs=[IMAGE],
            mounts=[
                (str(self.data_dir), "/data/db", "rw"),
                (str(self.secret_dir), SECRET_MOUNT, "ro"),
            ],
            environment={
                "MONGO_INITDB_ROOT_USERNAME": USER,
                "MONGO_INITDB_ROOT_PASSWORD_FILE": f"{SECRET_MOUNT}/mongodb-password",
            },
            container_port=CONTAINER_PORT,
            cpus=CPUS,
            memory=MEMORY,
            userns="keep-id:uid=999,gid=999",
            command=self.command,
            network=self.context.network,
        )
        # The entrypoint first runs a temporary server to create the user.
        self.container.wait_for_log("MongoDB init process complete", timeout=300)
        self.port = self.container.host_port(CONTAINER_PORT)
        deadline = time.monotonic() + 120
        while True:
            try:
                client = MongoBenchClient(self.spec())
                client.connection.command("admin", {"ping": 1})
                client.close()
                return
            except Exception:
                if time.monotonic() > deadline or not self.container.running():
                    raise
                time.sleep(0.5)

    def spec(self) -> dict:
        return {"engine": self.engine, "port": self.port, "user": USER, "password": self._password}

    def describe(self, client) -> dict:
        build = client.connection.command("admin", {"buildInfo": 1})
        options = client.connection.command("admin", {"getCmdLineOpts": 1}).get("parsed", {})
        status = client.connection.command("admin", {"serverStatus": 1})
        return {
            "product": "MongoDB Community Server",
            "version": build.get("version"),
            "image": {"reference": IMAGE, "tag": TAG, "platform_manifest": PLATFORM_MANIFEST},
            "server_command": self.command,
            "parsed_options": options,
            "storage_engine": (status.get("storageEngine") or {}).get("name"),
            "durability": DURABILITY,
            "cache": f"--wiredTigerCacheSizeGB {CACHE_GB}; WiredTiger block compression "
            "default (snappy)",
            "client": CLIENT,
        }

    def setup(self, client) -> None:
        client.connection.command(
            DATABASE,
            {
                "createIndexes": dataset.COLLECTION,
                "indexes": [
                    {"key": {"category": 1}, "name": "category"},
                    {"key": {"price": 1}, "name": "price"},
                    {
                        "key": {"description": "text"},
                        "name": "description_text",
                        "default_language": "none",
                    },
                ],
            },
        )

    def after_ingest(self, client) -> None:
        """MongoDB maintains planner state itself; nothing to run."""

    def checkpoint(self, client) -> None:
        client.connection.command("admin", {"fsync": 1})


class MongoBenchClient:
    name = CLIENT

    def __init__(self, spec: dict):
        self.connection = MongoConnection(
            "127.0.0.1", spec["port"], username=spec["user"], password=spec["password"]
        )

    def close(self) -> None:
        self.connection.close()

    def _command(self, body: dict) -> dict:
        return self.connection.command(DATABASE, body)

    @staticmethod
    def prepare_insert(documents: list) -> list:
        return [{"_id": item.id, **item.fields} for item in documents]

    def insert(self, payload: list) -> int:
        reply = self._command(
            {
                "insert": dataset.COLLECTION,
                "documents": payload,
                "ordered": True,
                "writeConcern": WRITE_CONCERN,
            }
        )
        if reply.get("n") != len(payload):
            raise RuntimeError("MongoDB inserted a different number of documents")
        return len(payload)

    def delete(self, identifiers: list) -> int:
        reply = self._command(
            {
                "delete": dataset.COLLECTION,
                "deletes": [{"q": {"_id": {"$in": identifiers}}, "limit": 0}],
                "ordered": True,
                "writeConcern": WRITE_CONCERN,
            }
        )
        return int(reply.get("n", 0))

    @staticmethod
    def _find(operation: tuple) -> dict:
        kind = operation[0]
        body = {"find": dataset.COLLECTION, "singleBatch": True}
        if kind == "get":
            return {**body, "filter": {"_id": operation[1]}, "limit": 1}
        if kind == "eq":
            return {**body, "filter": {"category": operation[1]}, "limit": dataset.QUERY_LIMIT}
        if kind == "range":
            return {
                **body,
                "filter": {"price": {"$gte": operation[1], "$lt": operation[2]}},
                "sort": {"price": 1},
                "limit": dataset.QUERY_LIMIT,
            }
        if kind == "text":
            return {
                **body,
                "filter": {"$text": {"$search": operation[1]}},
                "limit": dataset.QUERY_LIMIT,
            }
        raise ValueError(f"unknown query {kind}")

    def run(self, operation: tuple) -> int:
        kind = operation[0]
        if kind == "update":
            reply = self._command(
                {
                    "update": dataset.COLLECTION,
                    "updates": [{"q": {"_id": operation[1]}, "u": {"$inc": {"stock": 1}}}],
                    "ordered": True,
                    "writeConcern": WRITE_CONCERN,
                }
            )
            return int(reply.get("nModified", 0))
        if kind == "aggregate":
            return len(self.aggregate())
        return len(self._command(self._find(operation))["cursor"]["firstBatch"])

    def fetch(self, operation: tuple) -> list:
        rows = self._command(self._find(operation))["cursor"]["firstBatch"]
        return [
            (row["_id"], {key: value for key, value in row.items() if key != "_id"}) for row in rows
        ]

    def _aggregate(self, pipeline: list) -> list:
        reply = self._command({"aggregate": dataset.COLLECTION, "pipeline": pipeline, "cursor": {}})
        if reply["cursor"].get("id"):
            raise RuntimeError("aggregation result exceeded one batch")
        return reply["cursor"]["firstBatch"]

    def aggregate(self) -> list:
        return self._aggregate(
            [
                {
                    "$group": {
                        "_id": "$category",
                        "count": {"$sum": 1},
                        "avg_price": {"$avg": "$price"},
                    }
                },
                {"$sort": {"_id": 1}},
            ]
        )

    def stock_sum(self) -> int:
        rows = self._aggregate([{"$group": {"_id": None, "stock": {"$sum": "$stock"}}}])
        return int(rows[0]["stock"])

    def count(self) -> int:
        rows = self._aggregate([{"$count": "n"}])
        return int(rows[0]["n"]) if rows else 0

    def plans(self, operations: dict) -> dict:
        plans = {}
        for name in ("eq", "range", "text"):
            find = self._find(operations[name])
            find.pop("singleBatch")
            reply = self._command({"explain": find, "verbosity": "executionStats"})
            stats = reply.get("executionStats", {})
            plans[name] = {
                "winning_plan": _stages(reply.get("queryPlanner", {}).get("winningPlan", {})),
                "documents_examined": stats.get("totalDocsExamined"),
                "index_keys_examined": stats.get("totalKeysExamined"),
            }
        return plans


def _stages(plan: dict) -> str:
    """Compact stage chain such as ``LIMIT > FETCH > IXSCAN(category)``."""
    parts = []
    node = plan.get("queryPlan", plan)
    while isinstance(node, dict) and node:
        stage = node.get("stage", "?")
        if node.get("indexName"):
            stage += f"({node['indexName']})"
        parts.append(stage)
        children = node.get("inputStage") or (node.get("inputStages") or [None])[0]
        node = children
    return " > ".join(parts)
