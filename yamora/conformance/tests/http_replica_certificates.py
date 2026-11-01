"""Pure certificate-only entry point; no SDK or process supervisor imports."""

import sys
from pathlib import Path


def certificates(root):
    # Compose the committed Rust certificate recipe; never run setUpClass.
    from runpy import run_path

    fixture = Path(__file__).resolve().parents[2] / "drivers/rust/tests/support/fixture.py"
    run_path(str(fixture))["certificates"](root)
    for path in root.iterdir():
        path.chmod(0o600)


def main():
    if len(sys.argv) != 3 or sys.argv[1] != "--certificates":
        raise SystemExit("expected --certificates ROOT")
    certificates(Path(sys.argv[2]))


if __name__ == "__main__":
    main()
