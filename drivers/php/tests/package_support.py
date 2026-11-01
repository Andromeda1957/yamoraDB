"""Install a Composer-built archive into a separate, offline consumer."""

import json
import os
import shutil
import sys
import tarfile
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[4]
if (REPOSITORY / "tools/ci/yamora_driver_ci/process.py").is_file():
    sys.path.insert(0, str(REPOSITORY))

from tools.ci.yamora_driver_ci import process  # noqa: E402
from tools.ci.yamora_driver_ci.runner import package_task_root  # noqa: E402
from tools.ci.yamora_driver_ci.runner import scratch_parent  # noqa: E402
from tools.ci.yamora_driver_ci.runner import workspace  # noqa: E402


def package_anchor():
    configured = os.environ.get("YAMORA_PACKAGE_TASK_ROOT")
    if not configured:
        raise process.RunnerError("Set YAMORA_PACKAGE_TASK_ROOT to the managed task scratch root")
    anchor = scratch_parent(configured)
    if anchor != package_task_root(scratch_parent(os.environ["TMPDIR"])):
        raise process.RunnerError("package anchor must be the exact managed task root")
    return anchor


def packaged_artifact(case):
    if not os.environ.get("COMPOSER_PHAR"):
        raise RuntimeError("Set COMPOSER_PHAR to an existing verified official Composer PHAR")
    phar = Path(os.environ["COMPOSER_PHAR"]).resolve(strict=True)
    source = Path(__file__).resolve().parents[1]
    # Retained allocations must survive Contract's TemporaryDirectory and the
    # outer runner's disposable workspace, so allocate at their stable sibling.
    with workspace(package_anchor()) as root:
        stage = root / "source"
        shutil.copytree(source, stage, ignore=shutil.ignore_patterns("vendor", "__pycache__"))
        temporary = root / "tmp"
        temporary.mkdir()
        env = dict(
            os.environ,
            TMPDIR=str(temporary),
            COMPOSER_DISABLE_NETWORK="1",
            COMPOSER_NO_INTERACTION="1",
            COMPOSER_ROOT_VERSION="0.1.0",
        )
        env.pop("COMPOSER", None)
        for name in ("COMPOSER_HOME", "COMPOSER_CACHE_DIR"):
            directory = root / name.lower()
            directory.mkdir()
            env[name] = str(directory)

        def run(*arguments, cwd=root):
            return process.run(list(arguments), cwd=cwd, env=env, timeout=120)

        composer = ["php", str(phar), "--no-plugins", "--no-scripts", "--no-interaction"]
        run(*composer, "validate", cwd=stage)
        run(
            *composer,
            "archive",
            "--format=tar",
            "--dir=" + str(root),
            "--file=yamora-driver",
            cwd=stage,
        )
        artifact = root / "yamora-driver.tar"
        with tarfile.open(artifact) as archive:
            files = {member.name.removeprefix("./") for member in archive if member.isfile()}
            expected = {"composer.json", "LICENSE", "README.md", "examples/crud.php"}
            expected.update(
                str(path.relative_to(source)) for path in (source / "src").glob("*.php")
            )
            case.assertEqual(files, expected)
            metadata = json.load(archive.extractfile("composer.json"))
            case.assertEqual(metadata["version"], "0.1.0")
            case.assertEqual(metadata["license"], "MIT")
            case.assertEqual(
                archive.extractfile("LICENSE").read(), (source / "LICENSE").read_bytes()
            )
        consumer = root / "consumer"
        consumer.mkdir()
        package = dict(metadata, dist={"type": "tar", "url": artifact.as_uri()})
        (consumer / "composer.json").write_text(
            json.dumps(
                {
                    "name": "yamora/package-smoke",
                    "version": "0.1.0",
                    "require": {"yamora/driver": "0.1.0"},
                    "repositories": [
                        {"type": "package", "package": package},
                        {"packagist.org": False},
                    ],
                    "config": {"allow-plugins": False},
                }
            )
        )
        run(*composer, "install", "--no-dev", "--no-progress", cwd=consumer)
        probe = r"""
require 'vendor/autoload.php';
foreach (['Client', 'Document', 'ClusterClient', 'UncertainWriteException', 'BinaryClient',
          'BinaryConfig', 'BinaryResponse', 'BinaryEnvelope', 'CancellationToken', 'TlsOptions'] as $name) {
    $reflection = new ReflectionClass('Yamora\\' . $name);
    if (!str_starts_with($reflection->getFileName(), getcwd() . '/vendor/yamora/driver/src/')) {
        throw new RuntimeException('wrong package origin');
    }
}
echo 'IMPORT_OK';
"""
        case.assertEqual(run("php", "-r", probe, cwd=consumer), "IMPORT_OK")
        with case.daemon(mtls=True) as port:
            for name in ("ca.pem", "client.pem", "client.key"):
                shutil.copy2(case.root / name, root / name)
            env.update(
                {
                    "YAMORA_PORT": str(port),
                    "YAMORA_CA_FILE": str(root / "ca.pem"),
                    "YAMORA_CLIENT_CERT_FILE": str(root / "client.pem"),
                    "YAMORA_CLIENT_KEY_FILE": str(root / "client.key"),
                    "YAMORA_READ_TOKEN": "r" * 32,
                    "YAMORA_WRITE_TOKEN": "w" * 32,
                }
            )
            case.assertEqual(
                run("php", "vendor/yamora/driver/examples/crud.php", cwd=consumer), "CRUD_OK\n"
            )
