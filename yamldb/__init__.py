"""YamlDB administration and client package."""

from .client import YamlDBClient
from .client import YamlDBClientError

__all__ = ("YamlDBClient", "YamlDBClientError")
