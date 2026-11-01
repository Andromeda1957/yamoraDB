"""Private executable selection and certificate configuration cross process boundaries."""

import json
import os
import ssl
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.ci.yamora_driver_ci import process
from tools.ci.yamora_driver_ci.runner import scratch_parent
from tools.ci.yamora_driver_ci.runner import workspace
from yamora.conformance import runner
from yamora.conformance.contract import ConformanceError
from yamora.conformance.contract import empty_observation


class EnvironmentTests(unittest.TestCase):
    def test_default_python_imports_private_tree_despite_distinct_caller_checkout(self):
        source = Path(__file__).resolve().parents[2]
        with workspace(scratch_parent(os.environ["TMPDIR"])) as root:
            for name, elapsed in (("private", 41), ("caller", 43)):
                package = root / name / "yamora/conformance"
                package.mkdir(parents=True)
                (package.parent / "__init__.py").write_text("")
                (package / "__init__.py").write_text("")
                observation = empty_observation() | {"elapsed_ns": elapsed}
                (package / "python_adapter.py").write_text(
                    "print(" + repr(json.dumps(observation)) + ")\n"
                )
            output = root / "output"
            output.mkdir()
            script = """
import json, os, sys
from pathlib import Path
from types import SimpleNamespace
from yamora.conformance import runner, contract
root, private = map(Path, sys.argv[1:])
environment = {'PATH': os.defpath, 'PYTHONPATH': str(private),
               'TMPDIR': str(root), 'PYTHONDONTWRITEBYTECODE': '1'}
native = SimpleNamespace(root=root, env=environment, check_logs=lambda: None)
case = {'id': 'import-only', 'method': 'GET', 'fault': 'none',
        'cancel_mode': 'none', 'credential': 'read'}
prefix = contract.select_adapters(['python'], {})['python']
print(json.dumps(runner.invoke(prefix, native, 1, case, root, b'',
                              None, None, '01' * 16, None, 'python')))
"""
            result = process.run(
                [sys.executable, "-P", "-c", script, str(output), str(root / "private")],
                cwd=root / "caller",
                env={
                    "PATH": os.defpath,
                    "PYTHONPATH": str(source),
                    "TMPDIR": str(root),
                    "PYTHONDONTWRITEBYTECODE": "1",
                },
                timeout=10,
            )
            self.assertEqual(json.loads(result)["elapsed_ns"], 41, "PRIVATE_PYTHON_IMPORT")

    def test_adapter_preflight_uses_private_path_and_preserves_explicit_prefix(self):
        ambient = dict(os.environ)
        with workspace(scratch_parent(os.environ["TMPDIR"])) as root:
            tools = root / "tools"
            tools.mkdir()
            executable = tools / "private-conformance-python"
            executable.write_text(f"#!{sys.executable}\nprint('PRIVATE_ADAPTER_PATH_PROBE')\n")
            executable.chmod(0o700)
            environment = {"PATH": str(tools), "TMPDIR": str(root)}
            original = dict(environment)
            output = process.run([executable.name], cwd=root, env=environment, timeout=5)
            self.assertEqual(output.strip(), "PRIVATE_ADAPTER_PATH_PROBE")

            class ReachedNative(Exception):
                pass

            def admitted(prefix, environment):
                with patch.object(runner, "Native", side_effect=ReachedNative) as fixture:
                    try:
                        runner.execute(
                            sys.executable,
                            root,
                            ["python"],
                            {"python": prefix},
                            environment=environment,
                        )
                    except ReachedNative:
                        self.assertEqual(fixture.call_args.kwargs["environment"], environment)
                        return True
                    except ConformanceError as error:
                        self.assertEqual(str(error), "MISSING_ADAPTER_EXECUTABLE")
                        return False
                self.fail("preflight unexpectedly returned")

            prefix = [executable.name, "--private-wrapper-option"]
            self.assertTrue(admitted(prefix, environment), "PRIVATE_PATH_PREFLIGHT")
            self.assertEqual(prefix, [executable.name, "--private-wrapper-option"])
            self.assertFalse(admitted([executable.name], {**environment, "PATH": ""}))
            self.assertFalse(admitted(["python3"], environment), "NO_AMBIENT_PATH_FALLBACK")
            self.assertTrue(admitted([str(executable)], {**environment, "PATH": ""}))
            self.assertEqual(environment, original)
        self.assertEqual(dict(os.environ), ambient)

    def test_certificate_creation_uses_private_environment_and_configuration(self):
        ambient = dict(os.environ)
        source = Path(__file__).resolve().parents[2]
        with workspace(scratch_parent(os.environ["TMPDIR"])) as root:
            audit = root / "openssl-observations.jsonl"
            wrapper = f"""#!{sys.executable}
import json, os, sys
from pathlib import Path
names = ('PATH', 'HOME', 'TMPDIR', 'PYTHONPATH', 'OPENSSL_CONF', 'CERTIFICATE_MODE')
with Path(os.environ['CERTIFICATE_AUDIT']).open('a') as output:
    output.write(json.dumps({{name: os.environ.get(name) for name in names}}) + '\\n')
os.execv('/usr/bin/openssl', ['/usr/bin/openssl', *sys.argv[1:]])
"""
            environments = {}
            for name in ("ambient", "private"):
                base = root / name
                base.mkdir()
                tools, home, temporary = (base / part for part in ("tools", "home", "tmp"))
                for path in (tools, home, temporary):
                    path.mkdir()
                openssl = tools / "openssl"
                openssl.write_text(wrapper)
                openssl.chmod(0o700)
                config = base / "openssl.cnf"
                config.write_text(
                    "[req]\ndistinguished_name=dn\nx509_extensions=fixture\n[dn]\n"
                    f"[fixture]\n1.3.6.1.4.1.55555.1=ASN1:UTF8String:{name}-fixture\n"
                )
                environments[name] = {
                    "PATH": str(tools),
                    "HOME": str(home),
                    "TMPDIR": str(temporary),
                    "PYTHONPATH": str(source),
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "OPENSSL_CONF": str(config),
                    "CERTIFICATE_MODE": name,
                    "CERTIFICATE_AUDIT": str(audit),
                }
            private_file = root / "private-environment.json"
            private_file.write_text(json.dumps(environments["private"]))
            native_root = root / "certificates"
            native_root.mkdir()
            script = """
import json, sys
from pathlib import Path
from unittest.mock import patch
from yamora.conformance.tests import native
class CertificateStageComplete(Exception): pass
original_run = native.run
def certificate_only(argv, **kwargs):
    if '--init-disk' in argv:
        raise CertificateStageComplete
    return original_run(argv, **kwargs)
try:
    with patch.object(native, 'run', side_effect=certificate_only):
        native.Native(Path(sys.argv[1]), sys.executable,
                      environment=json.loads(Path(sys.argv[2]).read_text())).__enter__()
except CertificateStageComplete:
    print('CERTIFICATE_STAGE_ONLY')
else:
    raise AssertionError('certificate probe reached an unexpected stage')
"""
            output = process.run(
                [sys.executable, "-P", "-c", script, str(native_root), str(private_file)],
                cwd=root,
                env=environments["ambient"],
                timeout=40,
            )
            self.assertEqual(output.strip().splitlines()[-1], "CERTIFICATE_STAGE_ONLY")
            observations = [json.loads(line) for line in audit.read_text().splitlines()]
            self.assertEqual(len(observations), 8, "all existing certificate commands observed")
            self.assertEqual(
                {entry["CERTIFICATE_MODE"] for entry in observations},
                {"private"},
                "PRIVATE_CERTIFICATE_ENVIRONMENT",
            )
            for entry in observations:
                for key in entry:
                    wanted = str(native_root) if key == "TMPDIR" else environments["private"][key]
                    self.assertEqual(entry[key], wanted, key)
            ca = ssl.PEM_cert_to_DER_cert((native_root / "ca.pem").read_text())
            self.assertIn(b"private-fixture", ca, "PRIVATE_CERTIFICATE_CONFIG")
            self.assertNotIn(b"ambient-fixture", ca)
            self.assertEqual(json.loads(private_file.read_text()), environments["private"])
        self.assertEqual(dict(os.environ), ambient)
