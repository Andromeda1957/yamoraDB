"""``python -m yamora.benchmarks.compare``; guarded for spawned workers."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
