"""Build explicit local Go source and file-proxy artifacts, without publishing."""

import argparse
import gzip
import io
import json
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def inputs(root):
    root = root.resolve(strict=True)
    names = (root / "package-files.txt").read_text().splitlines()
    if not names or len(names) != len(set(names)):
        raise ValueError("invalid Go package manifest")
    result = []
    for name in names:
        relative = Path(name)
        path = root / relative
        if relative.is_absolute() or ".." in relative.parts or not name:
            raise ValueError("invalid Go package input")
        if any(p.is_symlink() for p in (path, *path.parents) if p != root and root in p.parents):
            raise ValueError("Go package inputs must not be symlinks")
        if not path.resolve(strict=True).is_relative_to(root) or not path.is_file():
            raise ValueError("Go package input is not a contained file")
        result.append((name, path.read_bytes()))
    return sorted(result)


def build(root, output):
    root, output = root.resolve(strict=True), output.resolve()
    if output.is_relative_to(root) or (output.exists() and any(output.iterdir())):
        raise ValueError("artifact output must be empty and outside source")
    selected = inputs(root)
    version = (root / "VERSION").read_text().strip()
    module = (root / "go.mod").read_text().splitlines()[0].removeprefix("module ")
    if version != "0.1.0" or module != "github.com/Andromeda1957/yamoraDB/drivers/go":
        raise ValueError("unsupported local Go package identity")
    output.mkdir(parents=True, exist_ok=True)
    escaped = "".join("!" + c.lower() if c.isupper() else c for c in module)
    proxy = output / "proxy" / escaped / "@v"
    proxy.mkdir(parents=True)
    prefix = module + "@v" + version + "/"
    with zipfile.ZipFile(
        proxy / f"v{version}.zip", "x", compression=zipfile.ZIP_DEFLATED
    ) as archive:
        for name, data in selected:
            info = zipfile.ZipInfo(prefix + name, (1980, 1, 1, 0, 0, 0))
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
    (proxy / f"v{version}.mod").write_bytes((root / "go.mod").read_bytes())
    (proxy / f"v{version}.info").write_text(
        json.dumps({"Version": "v" + version, "Time": "1970-01-01T00:00:00Z"}) + "\n"
    )
    (proxy / "list").write_text("v" + version + "\n")
    with (output / f"yamora-go-{version}.tar.gz").open("xb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as archive:
                for name, data in selected:
                    tar_info = tarfile.TarInfo(f"yamora-go-{version}/" + name)
                    tar_info.size, tar_info.mode = len(data), 0o644
                    archive.addfile(tar_info, io.BytesIO(data))
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(build(ROOT, args.output))


if __name__ == "__main__":
    main()
