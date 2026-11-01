"""PostgreSQL with one JSONB table, from the official image pinned by digest."""

from __future__ import annotations

import json
import time

from .. import dataset
from .base import CPUS
from .base import MEMORY
from .base import RunContext
from .base import Server

IMAGE = "docker.io/library/postgres@sha256:979bccfde35445db618c65107d27d08c6c21339d8dc3ad4c830c6633947be0e4"
TAG = "18.6-trixie"
PLATFORM_MANIFEST = "sha256:f4b419e350fd98d4a8429603295208976dea4c8fb8326d818d346d3e29f1db6f"
CONTAINER_PORT = 5432
DATABASE = "bench"
USER = "bench"
SECRET_MOUNT = "/run/benchmark-secrets"
SETTINGS = {
    "listen_addresses": "*",
    "shared_buffers": "256MB",
    "fsync": "on",
    "synchronous_commit": "on",
    "full_page_writes": "on",
    "wal_sync_method": "fdatasync",
    "max_connections": "40",
}
VERIFIED_SETTINGS = (
    "server_version",
    "fsync",
    "synchronous_commit",
    "full_page_writes",
    "wal_sync_method",
    "shared_buffers",
    "wal_level",
    "autovacuum",
)
DURABILITY = (
    "fsync=on, synchronous_commit=on, full_page_writes=on, wal_sync_method=fdatasync; every "
    "statement autocommits, so each insert batch, update and delete batch waits for its WAL flush."
)
CLIENT = "psycopg2 (C extension over libpq; one persistent connection per client process)"
TABLE = dataset.COLLECTION
SELECT_EQ = f"SELECT id, doc FROM {TABLE} WHERE doc->'category' = %s::jsonb LIMIT %s"
SELECT_RANGE = (
    f"SELECT id, doc FROM {TABLE} WHERE doc->'price' >= %s::jsonb AND doc->'price' < %s::jsonb "
    "ORDER BY doc->'price' LIMIT %s"
)
SELECT_TEXT = (
    f"SELECT id, doc FROM {TABLE} WHERE to_tsvector('simple', doc->>'description') "
    "@@ plainto_tsquery('simple', %s) LIMIT %s"
)


class PostgresServer(Server):
    engine = "postgresql"
    container_port = CONTAINER_PORT

    def __init__(self, context: RunContext, repetition: int):
        super().__init__(context, repetition)
        password_file = context.write_secret(self.secret_dir, "postgresql-password")
        self._password = password_file.read_text().strip()
        self.command = ["postgres"]
        for key, value in SETTINGS.items():
            self.command += ["-c", f"{key}={value}"]

    def start(self) -> None:
        self.container.start(
            image_or_rootfs=[IMAGE],
            mounts=[
                (str(self.data_dir), "/var/lib/postgresql", "rw"),
                (str(self.secret_dir), SECRET_MOUNT, "ro"),
            ],
            environment={
                "POSTGRES_USER": USER,
                "POSTGRES_DB": DATABASE,
                "POSTGRES_PASSWORD_FILE": f"{SECRET_MOUNT}/postgresql-password",
            },
            container_port=CONTAINER_PORT,
            cpus=CPUS,
            memory=MEMORY,
            userns="keep-id:uid=999,gid=999",
            command=self.command,
            network=self.context.network,
        )
        self.container.wait_for_log("PostgreSQL init process complete", timeout=300)
        self.port = self.container.host_port(CONTAINER_PORT)
        deadline = time.monotonic() + 120
        while True:
            try:
                PostgresBenchClient(self.spec()).close()
                return
            except Exception:
                if time.monotonic() > deadline or not self.container.running():
                    raise
                time.sleep(0.5)

    def spec(self) -> dict:
        return {"engine": self.engine, "port": self.port, "user": USER, "password": self._password}

    def describe(self, client) -> dict:
        settings = {}
        for name in VERIFIED_SETTINGS:
            client.cursor.execute(f"SHOW {name}")
            settings[name] = client.cursor.fetchone()[0]
        import psycopg2

        return {
            "product": "PostgreSQL",
            "version": settings["server_version"],
            "image": {"reference": IMAGE, "tag": TAG, "platform_manifest": PLATFORM_MANIFEST},
            "server_command": self.command,
            "settings": settings,
            "schema": f"{TABLE}(id text PRIMARY KEY, doc jsonb NOT NULL); B-tree expression "
            "indexes on doc->'category' and doc->'price'; GIN on "
            "to_tsvector('simple', doc->>'description')",
            "durability": DURABILITY,
            "cache": "shared_buffers=256MB, plus the OS page cache inside the container limit",
            "client": f"{CLIENT}; psycopg2 {getattr(psycopg2, '__version__', 'unknown').split()[0]}",
        }

    def setup(self, client) -> None:
        cursor = client.cursor
        cursor.execute(f"CREATE TABLE {TABLE} (id text PRIMARY KEY, doc jsonb NOT NULL)")
        cursor.execute(f"CREATE INDEX {TABLE}_category ON {TABLE} ((doc->'category'))")
        cursor.execute(f"CREATE INDEX {TABLE}_price ON {TABLE} ((doc->'price'))")
        cursor.execute(
            f"CREATE INDEX {TABLE}_description ON {TABLE} "
            "USING gin (to_tsvector('simple', doc->>'description'))"
        )

    def after_ingest(self, client) -> None:
        """Standard practice after a bulk load: give the planner statistics."""
        client.cursor.execute(f"ANALYZE {TABLE}")

    def checkpoint(self, client) -> None:
        client.cursor.execute("CHECKPOINT")


class PostgresBenchClient:
    name = CLIENT

    def __init__(self, spec: dict):
        import psycopg2
        import psycopg2.extras

        self._execute_values = psycopg2.extras.execute_values
        self.connection = psycopg2.connect(
            host="127.0.0.1",
            port=spec["port"],
            dbname=DATABASE,
            user=spec["user"],
            password=spec["password"],
            connect_timeout=30,
            sslmode="disable",
            application_name="yamora-comparative-benchmark",
        )
        self.connection.autocommit = True
        self.cursor = self.connection.cursor()

    def close(self) -> None:
        try:
            self.cursor.close()
        finally:
            self.connection.close()

    @staticmethod
    def prepare_insert(documents: list) -> list:
        return [(item.id, dataset.to_json(item.fields)) for item in documents]

    def insert(self, payload: list) -> int:
        # One multi-row INSERT statement, committed on its own in autocommit mode.
        self._execute_values(
            self.cursor,
            f"INSERT INTO {TABLE} (id, doc) VALUES %s",
            payload,
            template="(%s, %s::jsonb)",
            page_size=len(payload),
        )
        if self.cursor.rowcount != len(payload):
            raise RuntimeError("PostgreSQL inserted a different number of rows")
        return len(payload)

    def delete(self, identifiers: list) -> int:
        self.cursor.execute(f"DELETE FROM {TABLE} WHERE id = ANY(%s)", (identifiers,))
        return self.cursor.rowcount

    def _query(self, operation: tuple):
        kind = operation[0]
        if kind == "get":
            return f"SELECT id, doc FROM {TABLE} WHERE id = %s", (operation[1],)
        if kind == "eq":
            return SELECT_EQ, (json.dumps(operation[1]), dataset.QUERY_LIMIT)
        if kind == "range":
            return SELECT_RANGE, (str(operation[1]), str(operation[2]), dataset.QUERY_LIMIT)
        if kind == "text":
            return SELECT_TEXT, (operation[1], dataset.QUERY_LIMIT)
        raise ValueError(f"unknown query {kind}")

    def run(self, operation: tuple) -> int:
        kind = operation[0]
        if kind == "update":
            self.cursor.execute(
                f"UPDATE {TABLE} SET doc = jsonb_set(doc, '{{stock}}', "
                "to_jsonb((doc->>'stock')::bigint + 1)) WHERE id = %s",
                (operation[1],),
            )
            return self.cursor.rowcount
        if kind == "aggregate":
            return len(self.aggregate())
        self.cursor.execute(*self._query(operation))
        return len(self.cursor.fetchall())

    def fetch(self, operation: tuple) -> list:
        self.cursor.execute(*self._query(operation))
        return [(row[0], row[1]) for row in self.cursor.fetchall()]

    def aggregate(self) -> list:
        self.cursor.execute(
            f"SELECT doc->>'category', count(*), avg((doc->>'price')::numeric) FROM {TABLE} "
            "GROUP BY 1 ORDER BY 1"
        )
        return [
            {"_id": category, "count": count, "avg_price": float(average)}
            for category, count, average in self.cursor.fetchall()
        ]

    def stock_sum(self) -> int:
        self.cursor.execute(f"SELECT coalesce(sum((doc->>'stock')::bigint), 0) FROM {TABLE}")
        return int(self._single_value())

    def count(self) -> int:
        self.cursor.execute(f"SELECT count(*) FROM {TABLE}")
        return int(self._single_value())

    def plans(self, operations: dict) -> dict:
        plans = {}
        for name in ("eq", "range", "text"):
            query, parameters = self._query(operations[name])
            self.cursor.execute("EXPLAIN (ANALYZE, FORMAT JSON) " + query, parameters)
            plan = self._single_value()[0]["Plan"]
            plans[name] = {"plan": _nodes(plan)}
        return plans

    def _single_value(self):
        row = self.cursor.fetchone()
        if row is None:
            raise RuntimeError("PostgreSQL returned no row for a single-value query")
        return row[0]


def _nodes(plan: dict) -> str:
    parts = []
    node: object = plan
    while isinstance(node, dict):
        label = node.get("Node Type", "?")
        if node.get("Index Name"):
            label += f"({node['Index Name']})"
        parts.append(label)
        children = node.get("Plans") or []
        node = children[0] if children else None
    return " > ".join(parts)
