"""Exact-identity Podman lifecycle for benchmark containers.

Every container carries this run's random label and a unique name. Cleanup
removes only those exact names, then proves no container with the run label
remains. Commands are fixed argument lists without a shell; secret values are
never arguments, environment values or log lines (servers read them from
read-only mounted files).
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass
from dataclasses import field
from pathlib import Path

from .commands import run_fixed

LABEL = "io.yamora.comparative-benchmark.run"
ENGINE_LABEL = "io.yamora.comparative-benchmark.engine"
OWNER_PORT = 8000  # owner-only development server; never published or used
_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
_IMAGE = re.compile(r"docker\.io/library/[a-z0-9]+@sha256:[0-9a-f]{64}")
COMMAND_TIMEOUT = 300


class PodmanError(RuntimeError):
    pass


def podman_environment() -> dict:
    """Podman stages pulls under TMPDIR; give it the physical scratch path.

    The repository scratch wrapper exposes TMPDIR as a short descriptor path
    for Unix sockets, which Podman's systemd-scoped helpers cannot create
    directories under.
    """
    environment = dict(os.environ)
    physical = environment.get("ANDROMEDA_SCRATCH_DIRECTORY")
    if physical:
        environment["TMPDIR"] = physical
    return environment


def run(arguments: list, *, timeout: float = COMMAND_TIMEOUT, check: bool = True) -> str:
    if not arguments or any(not isinstance(item, str) for item in arguments):
        raise PodmanError("podman arguments must be strings")
    completed = run_fixed(["podman", *arguments], timeout=timeout, env=podman_environment())
    if check and completed.returncode != 0:
        detail = completed.stderr.strip().splitlines()[-1:] or ["no error output"]
        raise PodmanError(f"podman {arguments[0]} failed: {detail[0][:300]}")
    return completed.stdout


def version() -> str:
    return run(["version", "--format", "{{.Client.Version}}"]).strip()


def image_identity(reference: str) -> dict:
    """The local image ID and digests for a pinned reference, without pulling."""
    if not _IMAGE.fullmatch(reference):
        raise PodmanError("benchmark images must be docker.io/library references pinned by digest")
    output = run(["image", "inspect", reference], check=False)
    try:
        inspected = json.loads(output) if output.strip() else []
    except json.JSONDecodeError as error:
        raise PodmanError("podman returned invalid image metadata") from error
    if not inspected:
        raise PodmanError(f"image {reference} is not present; run the harness 'pull' command first")
    image = inspected[0]
    return {
        "reference": reference,
        "image_id": image.get("Id"),
        "repo_digests": sorted(image.get("RepoDigests") or []),
        "architecture": image.get("Architecture"),
        "os": image.get("Os"),
        "created": image.get("Created"),
    }


def pull(reference: str) -> None:
    if not _IMAGE.fullmatch(reference):
        raise PodmanError("benchmark images must be pinned by digest")
    run(["pull", "--quiet", reference], timeout=1800)


@dataclass
class Container:
    """One detached benchmark container and the arguments that started it."""

    name: str
    run_label: str
    engine: str
    arguments: list = field(default_factory=list)
    started: bool = False

    def __post_init__(self):
        if not _NAME.fullmatch(self.name) or not _NAME.fullmatch(self.run_label):
            raise PodmanError("container names and labels must be lowercase identifiers")

    def start(
        self,
        *,
        image_or_rootfs: list,
        mounts: list,
        environment: dict,
        container_port: int,
        cpus: str,
        memory: str,
        userns: str,
        command: list,
        network: str,
        address: str | None = None,
    ) -> None:
        arguments = [
            "run",
            "--detach",
            "--name",
            self.name,
            "--label",
            f"{LABEL}={self.run_label}",
            "--label",
            f"{ENGINE_LABEL}={self.engine}",
            "--userns",
            userns,
            "--cpus",
            cpus,
            "--memory",
            memory,
            "--memory-swap",
            memory,
            "--image-volume",
            "ignore",
            "--network",
            network,
            # The only host-side listener: an ephemeral IPv4 loopback port.
            "--publish",
            f"127.0.0.1::{container_port}",
        ]
        if address is not None:
            arguments += ["--ip", address]
        for source, target, mode in mounts:
            if mode not in ("ro", "rw"):
                raise PodmanError("mount mode must be ro or rw")
            arguments += ["--volume", f"{source}:{target}:{mode}"]
        for key, value in environment.items():
            if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key) or "\n" in value:
                raise PodmanError("invalid container environment entry")
            arguments += ["--env", f"{key}={value}"]
        arguments += [*image_or_rootfs, *command]
        self.arguments = arguments
        run(arguments)
        self.started = True

    def host_port(self, container_port: int) -> int:
        output = run(["port", self.name, f"{container_port}/tcp"]).strip().splitlines()
        if not output:
            raise PodmanError("container port was not published")
        host, _, port_text = output[0].rpartition(":")
        port = int(port_text)
        if host != "127.0.0.1" or not 1024 <= port <= 65535 or port == OWNER_PORT:
            raise PodmanError("container port must be an ephemeral IPv4 loopback port")
        return port

    def pid(self) -> int:
        value = run(["inspect", "--format", "{{.State.Pid}}", self.name]).strip()
        pid = int(value)
        if pid <= 1:
            raise PodmanError("container has no running process")
        return pid

    def running(self) -> bool:
        output = run(["inspect", "--format", "{{.State.Running}}", self.name], check=False)
        return output.strip() == "true"

    def logs(self, tail: int = 200) -> str:
        completed = run_fixed(
            ["podman", "logs", "--tail", str(tail), self.name],
            timeout=60,
            env=podman_environment(),
        )
        return completed.stdout + completed.stderr

    def wait_for_log(self, marker: str, *, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if marker in self.logs(tail=2000):
                return
            if not self.running():
                raise PodmanError(f"{self.engine} container exited during startup")
            time.sleep(0.5)
        raise PodmanError(f"{self.engine} did not log its startup marker in time")

    def remove(self) -> None:
        if not self.started:
            return
        run(["rm", "--force", "--time", "20", "--volumes", self.name], check=False, timeout=120)
        self.started = False


def remaining(run_label: str) -> list:
    """Names of any container still carrying this run's label."""
    output = run(
        ["ps", "--all", "--filter", f"label={LABEL}={run_label}", "--format", "{{.Names}}"],
        check=False,
    )
    return [line for line in output.splitlines() if line.strip()]


def create_network(name: str, run_label: str) -> str:
    """A private bridge network for this run; returns its IPv4 subnet.

    Engines share one network path: each listens on a private address inside
    it and is reachable from the host only through its loopback publication.
    """
    if not _NAME.fullmatch(name):
        raise PodmanError("network names must be lowercase identifiers")
    run(["network", "create", "--label", f"{LABEL}={run_label}", name])
    output = run(["network", "inspect", name, "--format", "{{range .Subnets}}{{.Subnet}} {{end}}"])
    subnets = [item for item in output.split() if "." in item]
    if not subnets:
        remove_network(name)
        raise PodmanError("benchmark network has no IPv4 subnet")
    return subnets[0]


def remove_network(name: str) -> None:
    run(["network", "rm", "--force", name], check=False, timeout=120)


def remaining_networks(run_label: str) -> list:
    output = run(
        ["network", "ls", "--filter", f"label={LABEL}={run_label}", "--format", "{{.Name}}"],
        check=False,
    )
    return [line for line in output.splitlines() if line.strip()]


def run_once(
    *,
    run_label: str,
    engine: str,
    name: str,
    image_or_rootfs: list,
    mounts: list,
    userns: str,
    command: list,
    timeout: float = 600,
) -> str:
    """A foreground, auto-removed helper container (for example ``--init-disk``)."""
    if not _NAME.fullmatch(name):
        raise PodmanError("container names must be lowercase identifiers")
    arguments = [
        "run",
        "--rm",
        "--name",
        name,
        "--label",
        f"{LABEL}={run_label}",
        "--label",
        f"{ENGINE_LABEL}={engine}",
        "--userns",
        userns,
        "--network",
        "none",
        "--image-volume",
        "ignore",
    ]
    for source, target, mode in mounts:
        arguments += ["--volume", f"{source}:{target}:{mode}"]
    return run([*arguments, *image_or_rootfs, *command], timeout=timeout)


def scratch_root() -> Path:
    value = os.environ.get("ANDROMEDA_SCRATCH_DIRECTORY")
    if not value:
        raise PodmanError(
            "run the harness through agent/scratch_environment.py, which provides "
            "ANDROMEDA_SCRATCH_DIRECTORY, or pass --work-root"
        )
    return Path(value)
