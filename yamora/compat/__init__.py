"""Compatibility imports for applications migrating from yamldb to yamora."""

import sys

import yamora
from yamora import YamlDBClient
from yamora import YamlDBClientError
from yamora import YamoraClient
from yamora import YamoraClientError
from yamora import client as _client

__path__ = yamora.__path__
client = _client
sys.modules["yamldb.client"] = _client

__all__ = ("YamoraClient", "YamoraClientError", "YamlDBClient", "YamlDBClientError")
