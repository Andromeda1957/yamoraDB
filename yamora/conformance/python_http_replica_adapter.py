"""Public HTTP replica SDK observer. Launch with -P -m and an explicit PYTHONPATH.

Implements ADAPTER_HTTP_REPLICA_V2.md; never sends HTTP or retries independently.
The caller-reissue state is private session state, not an SDK prepared envelope.
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
import signal
import ssl
import stat
import sys
import threading
import time

from yamora.client import YamlDBClientError
from yamora.cluster_client import YamoraClusterClient
from yamora.cluster_client import YamoraUncertainWriteError

LINE_LIMIT = 16384
FILE_LIMIT = 131072
COMMAND_SCHEMA = "yamora-http-replica-command/2"
IDENTIFIER = re.compile(r"[a-z0-9-]{1,128}\Z")
REQUEST_ID = re.compile(r"[0-9a-f]{32}\Z")
ETAG = re.compile(r'"[0-9a-f]{16}"\Z')
SOURCE = re.compile(r"input/[a-z0-9-]{1,64}\.bin\Z")
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def require(condition):
    if not condition:
        raise ValueError("invalid adapter input")


def exact(value, keys):
    require(type(value) is dict and set(value) == set(keys))


def identifier(value):
    return type(value) is str and REQUEST_ID.fullmatch(value) and value != "0" * 32


def decode(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result

    def constant(_):
        raise ValueError("only integer JSON numbers are accepted")

    value = json.loads(
        data.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant, parse_float=constant
    )
    pending = [(value, 1)]
    while pending:
        item, depth = pending.pop()
        require(depth <= 12)
        if isinstance(item, (dict, list)):
            pending.extend(
                (child, depth + 1) for child in (item.values() if isinstance(item, dict) else item)
            )
    return value


class Files:
    """Descriptor-relative, no-symlink file access under the runner's root."""

    def __init__(self, root):
        require(type(root) is str and root.startswith("/") and root != "/")
        parts = root.split("/")[1:]
        require(all(part and part not in (".", "..") for part in parts))
        fd = os.open("/", DIRECTORY_FLAGS)
        try:
            for part in parts:
                following = os.open(part, DIRECTORY_FLAGS, dir_fd=fd)
                os.close(fd)
                fd = following
        except BaseException:
            os.close(fd)
            raise
        self.fd = fd

    def close(self):
        os.close(self.fd)

    def directory(self, name):
        return os.open(name, DIRECTORY_FLAGS, dir_fd=self.fd)

    def read(self, name, limit=FILE_LIMIT):
        parts = name.split("/")
        require(all(part and part not in (".", "..") for part in parts))
        parent = os.dup(self.fd)
        try:
            for part in parts[:-1]:
                following = os.open(part, DIRECTORY_FLAGS, dir_fd=parent)
                os.close(parent)
                parent = following
            fd = os.open(parts[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=parent)
            with os.fdopen(fd, "rb") as handle:
                require(stat.S_ISREG(os.fstat(handle.fileno()).st_mode))
                data = handle.read(limit + 1)
            require(len(data) <= limit)
            return data
        finally:
            os.close(parent)

    @staticmethod
    def write(directory, data):
        require(type(data) is bytes and len(data) <= FILE_LIMIT)
        fd = os.open(
            "body.bin",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory,
        )
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)


def configuration(files):
    config = decode(files.read("config.json", LINE_LIMIT))
    exact(
        config,
        (
            "schema",
            "cluster_id",
            "voters",
            "seeds",
            "tls",
            "tokens",
            "timeout_ms",
            "attempt_timeout_ms",
        ),
    )
    require(config["schema"] == "yamora-http-replica-config/2")
    require(identifier(config["cluster_id"]))
    for key, expected in (("voters", 3), ("timeout_ms", 15000), ("attempt_timeout_ms", 3000)):
        require(type(config[key]) is int and config[key] == expected)
    seeds = config["seeds"]
    require(type(seeds) is list and len(seeds) == 3)
    nodes, ports = set(), set()
    for seed in seeds:
        exact(seed, ("host", "port", "node"))
        require(seed["host"] == "127.0.0.1")
        require(
            type(seed["port"]) is int
            and 1 <= seed["port"] <= 65535
            and seed["port"] != 8000
            and seed["port"] not in ports
        )
        require(type(seed["node"]) is int and 1 <= seed["node"] <= 3 and seed["node"] not in nodes)
        ports.add(seed["port"])
        nodes.add(seed["node"])
    require(
        config["tls"] == {"ca_file": "ca.pem", "cert_file": "client.pem", "key_file": "client.key"}
    )
    require(config["tokens"] == {"read_file": "read.token", "write_file": "write.token"})
    # Check every fixed credential file before passing its anchored descriptor
    # path to APIs which accept file names rather than bytes.
    for name in ("ca.pem", "client.pem", "client.key", "read.token", "write.token"):
        files.read(name, 512 if name.endswith(".token") else LINE_LIMIT)
    return config


def cluster_client(files, config):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(cadata=files.read("ca.pem", LINE_LIMIT).decode("ascii"))
    # The root is held open and all components were checked. The SDK also rejects
    # symlink token leaves. No credentials enter observations or diagnostics.
    anchored = f"/proc/self/fd/{files.fd}"
    descriptors = []
    try:
        for name in ("client.pem", "client.key"):
            descriptor = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=files.fd)
            descriptors.append(descriptor)
            metadata = os.fstat(descriptor)
            require(stat.S_ISREG(metadata.st_mode) and metadata.st_size <= LINE_LIMIT)
        context.load_cert_chain(*(f"/proc/self/fd/{fd}" for fd in descriptors))
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
    return YamoraClusterClient(
        seeds=[(seed["host"], seed["port"]) for seed in config["seeds"]],
        tls_context=context,
        retry_timeout=15,
        timeout=3,
        auth_token_file=anchored + "/read.token",
        write_auth_token_file=anchored + "/write.token",
    )


@dataclasses.dataclass(frozen=True)
class Primitive:
    method: str
    collection: str
    document: str
    source: bytes | None
    request_id: str | None
    if_match: str | None
    if_none_match: str | None

    def arguments(self, request_id):
        options = {"request_id": request_id}
        if self.if_match is not None:
            options["etag"] = self.if_match[1:-1]
        if self.method == "PUT":
            options["create_only"] = self.if_none_match == "*"
            return (self.collection, self.document, self.source), options
        if self.method == "PATCH":
            # New mutable arguments for each invocation; the saved bytes never
            # alias SDK-owned maps, even if an API were to mutate its argument.
            return (self.collection, self.document, decode(self.source)), options
        if self.method == "GET":
            return (self.collection, self.document), {}
        return (self.collection, self.document), options


def primitive(command, files):
    exact(
        command,
        (
            "schema",
            "seq",
            "action",
            "method",
            "collection",
            "document",
            "source_file",
            "request_id",
            "if_match",
            "if_none_match",
        ),
    )
    method = command["method"]
    require(type(method) is str and method in ("GET", "PUT", "PATCH", "DELETE"))
    for key in ("collection", "document"):
        require(type(command[key]) is str and IDENTIFIER.fullmatch(command[key]))
    require(method == "GET" or command["collection"] != "yamldb-system")
    request_id, match, none = (command[key] for key in ("request_id", "if_match", "if_none_match"))
    require(request_id is None or identifier(request_id))
    require(match is None or type(match) is str and ETAG.fullmatch(match))
    require(none is None or type(none) is str and none == "*")
    require(none is None or method == "PUT" and match is None)
    require(method != "GET" or request_id is None and match is None and none is None)
    source = command["source_file"]
    if method in ("PUT", "PATCH"):
        require(type(source) is str and SOURCE.fullmatch(source))
        source = files.read(source)
        require(len(source) > 0)
        source.decode("utf-8")
        if method == "PATCH":
            value = decode(source)
            exact(value, ("$inc",))
            exact(value["$inc"], ("n",))
            require(type(value["$inc"]["n"]) is int and value["$inc"]["n"] == 1)
    else:
        require(source is None)
    return Primitive(
        method, command["collection"], command["document"], source, request_id, match, none
    )


def observation(command):
    return {
        "schema": "yamora-http-replica-observation/2",
        "seq": command["seq"],
        "action": command["action"],
        "outcome": "success",
        "error_kind": None,
        "elapsed_ns": 0,
        "api": {"status": None, "body_file": None, "etag": None, "revision": None, "receipt": None},
        "sdk_request_id": None,
        "envelope": None,
        "recovery_mode": None,
        "recovery_handle": None,
    }


class Session:
    def __init__(self, files, client):
        self.files, self.client = files, client
        self.sequence = 0
        self.handles = {}

    def close(self):
        # Python's public HTTP SDK closes each connection inside the call and
        # has no Close API. Discard retained exceptions and primitive state.
        self.handles.clear()
        self.client = None

    def execute(self, command):
        require(type(command) is dict)
        require(command.get("schema") == COMMAND_SCHEMA)
        require(
            type(command.get("seq")) is int
            and command["seq"] == self.sequence + 1
            and command["seq"] <= 64
        )
        action = command.get("action")
        require(type(action) is str)
        result = observation(command)
        error = None
        if action == "close":
            exact(command, ("schema", "seq", "action"))
            self.close()
            result["outcome"] = "closed"
            self.sequence += 1
            return result
        if action == "call":
            call = primitive(command, self.files)
            request_id = call.request_id
        else:
            exact(command, ("schema", "seq", "action", "handle"))
            require(
                action == "recover"
                and type(command["handle"]) is str
                and command["handle"] in self.handles
            )
            call, error = self.handles[command["handle"]]
            request_id = error.request_id
            result.update(recovery_mode="caller-reissue", recovery_handle=command["handle"])
        args, options = call.arguments(request_id)
        directory_name = f"call-{command['seq']:06d}"
        directory = self.files.directory(directory_name)
        try:
            invoke = getattr(self.client, call.method.lower())
            started = time.monotonic_ns()
            try:
                value = invoke(*args, **options)
                result["elapsed_ns"] = time.monotonic_ns() - started
            except YamoraUncertainWriteError as uncertain:
                result["elapsed_ns"] = time.monotonic_ns() - started
                require(call.method != "GET" and identifier(uncertain.request_id))
                if action == "call":
                    require(len(self.handles) < 16)
                    handle = f"h{len(self.handles) + 1}"
                    self.handles[handle] = (call, uncertain)
                    result.update(recovery_mode="caller-reissue", recovery_handle=handle)
                result.update(outcome="uncertain", sdk_request_id=uncertain.request_id)
                return result
            except YamlDBClientError as failure:
                result["elapsed_ns"] = time.monotonic_ns() - started
                kind = (
                    "status"
                    if failure.status is not None
                    else ("transport" if failure.transport else "protocol")
                )
                result.update(outcome=kind, error_kind=kind)
                result["api"]["status"] = failure.status
                return result
            if call.method == "GET":
                self.files.write(directory, value)
                result["api"]["body_file"] = directory_name + "/body.bin"
            elif call.method in ("PUT", "PATCH"):
                require(type(value) is dict)
                result["api"].update(
                    receipt=value, etag=value.get("etag"), revision=value.get("revision")
                )
            self.sequence += 1
            return result
        finally:
            os.close(directory)
            # Handled SDK exceptions also consume exactly one sequence number.
            self.sequence = command["seq"]


def watchdog():
    os.write(2, b"HTTP replica adapter command watchdog expired\n")
    os._exit(2)


def main(argv=None):
    files = session = None
    try:
        arguments = sys.argv[1:] if argv is None else argv
        require(len(arguments) == 4)
        require(set(arguments[::2]) == {"--config", "--root"})
        options = dict(zip(arguments[::2], arguments[1::2], strict=True))
        require(options["--config"] == options["--root"] + "/config.json")
        files = Files(options["--root"])
        session = Session(files, cluster_client(files, configuration(files)))
        while True:
            line = sys.stdin.buffer.readline(LINE_LIMIT + 1)
            require(0 < len(line) <= LINE_LIMIT and line.endswith(b"\n") and b"\r" not in line)
            timer = threading.Timer(25, watchdog)
            timer.daemon = True
            timer.start()
            try:
                result = session.execute(decode(line))
                encoded = (
                    json.dumps(
                        result, ensure_ascii=True, allow_nan=False, separators=(",", ":")
                    ).encode("utf-8")
                    + b"\n"
                )
                require(len(encoded) <= LINE_LIMIT)
                sys.stdout.buffer.write(encoded)
                sys.stdout.buffer.flush()
                if result["outcome"] == "closed":
                    return 0
            finally:
                timer.cancel()
                timer.join()
    except (Exception, KeyboardInterrupt):
        print("HTTP replica adapter input or infrastructure failure", file=sys.stderr)
        return 2
    finally:
        if session is not None:
            session.close()
        if files is not None:
            files.close()


if __name__ == "__main__":

    def interrupted(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    raise SystemExit(main())
