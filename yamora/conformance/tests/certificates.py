"""Reuse the existing certificate recipe inside a supervised private environment."""

import sys
from pathlib import Path

from .certificate_recipe import certs


def main():
    try:
        if len(sys.argv) != 2:
            raise ValueError("one certificate directory required")
        root = Path(sys.argv[1])
        if not root.is_absolute() or not root.is_dir() or root.is_symlink():
            raise ValueError("existing absolute certificate directory required")
        certs(root)
        return 0
    except Exception:
        print("Private certificate fixture failed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
