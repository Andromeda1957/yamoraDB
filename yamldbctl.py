#!/usr/bin/env python3
"""Compatibility alias and executable for YamoraDB administration."""

import importlib
import sys

_module_name = f"{__package__}.yamoractl" if __package__ else "yamoractl"
_implementation = importlib.import_module(_module_name)

if __name__ == "__main__":
    raise SystemExit(_implementation.main())
else:
    # Expose the complete implementation rather than a main-only facade. Under
    # ``yamldb`` its relative imports stay in that compatibility namespace;
    # the client module itself is explicitly shared with the canonical yamora package.
    sys.modules[__name__] = _implementation
