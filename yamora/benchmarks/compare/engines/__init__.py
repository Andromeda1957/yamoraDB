"""The three compared engines and their benchmark clients."""

from __future__ import annotations

ENGINES = ("yamora", "mongodb", "postgresql")


def open_client(spec: dict):
    """Create one engine client from a picklable connection specification."""
    engine = spec["engine"]
    if engine == "yamora":
        from .yamora_engine import YamoraBenchClient

        return YamoraBenchClient(spec)
    if engine == "mongodb":
        from .mongodb import MongoBenchClient

        return MongoBenchClient(spec)
    if engine == "postgresql":
        from .postgresql import PostgresBenchClient

        return PostgresBenchClient(spec)
    raise ValueError(f"unknown engine {engine!r}")
