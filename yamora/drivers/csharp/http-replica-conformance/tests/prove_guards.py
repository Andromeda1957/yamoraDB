"""Prove behavioral controls red under three adapter-only mutations, then restore.

No SDK source is mutated. Compiler/setup/watchdog failures cannot satisfy red.
Run only in the assigned canonical worker tree with its exact TMPDIR.
"""

import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
REPO = HERE.parents[3]
SCRATCH = Path("/var/tmp/andromeda-work/yamora-http-adapters-php-csharp")
PHP = REPO / "yamora/drivers/php/conformance/http_replica.php"
CSHARP = HERE / "Program.cs"


def main():
    if (
        os.environ.get("TMPDIR") != str(SCRATCH)
        or REPO.name != "website-agent-yamora-http-adapters-php-csharp"
    ):
        raise RuntimeError("proof requires assigned tree and exact task TMPDIR")
    dotnet = (
        Path(subprocess.check_output(["mise", "where", "dotnet"], text=True).strip()) / "dotnet"
    )
    environment = dict(
        os.environ,
        DOTNET_CLI_HOME=str(SCRATCH / "dotnet-home"),
        DOTNET_SKIP_FIRST_TIME_EXPERIENCE="1",
        DOTNET_CLI_TELEMETRY_OPTOUT="1",
        DOTNET_GENERATE_ASPNET_CERTIFICATE="false",
        PYTHONDONTWRITEBYTECODE="1",
        PATH=str(dotnet.parent) + os.pathsep + os.environ["PATH"],
        YAMORA_HTTP_REPLICA_TEST_LANGUAGE="both",
        YAMORA_HTTP_REPLICA_PHP_ADAPTER=str(PHP),
        YAMORA_HTTP_REPLICA_CSHARP_DLL=str(SCRATCH / "build/bin/HttpReplica/debug/HttpReplica.dll"),
    )

    def build():
        subprocess.run(
            [
                str(dotnet),
                "build",
                str(HERE / "HttpReplica.csproj"),
                "--artifacts-path",
                str(SCRATCH / "build"),
                "--nologo",
                "--verbosity",
                "quiet",
            ],
            env=environment,
            check=True,
            timeout=90,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def run_test(name):
        return subprocess.run(
            [sys.executable, str(HERE / "tests/test_http_replica.py"), "AdapterTests." + name],
            env=environment,
            capture_output=True,
            timeout=90,
        )

    originals = {PHP: PHP.read_text(), CSHARP: CSHARP.read_text()}
    mutations = [
        (
            "missing actual SDK uncertainty ID",
            "test_actual_uncertainty_retains_id_conditions_and_bytes",
            "None is not an instance of <class 'str'>",
            {
                PHP: ("$o['sdk_request_id']=$e->requestId;", "$o['sdk_request_id']=null;"),
                CSHARP: (
                    "observation.sdk_request_id = error.RequestId;",
                    "observation.sdk_request_id = null;",
                ),
            },
        ),
        (
            "fresh primitive instead of retained SDK recovery",
            "test_actual_uncertainty_retains_id_conditions_and_bytes",
            "recovery changed captured SDK bytes",
            {
                PHP: (
                    "$this->client->recover($failure)",
                    "$this->client->execute($this->client->prepareMutation('patch', ['manifests','counter',(object)['$inc'=>(object)['n'=>99]]]))",
                ),
                CSHARP: (
                    "await client.RecoverAsync(recovery)",
                    'await client.PatchAsync("manifests", "counter", JsonSerializer.SerializeToElement(new Dictionary<string, object> { ["$inc"] = new { n = 99 } }))',
                ),
            },
        ),
        (
            "invented ordinary success status",
            "test_success_and_honest_exposure",
            "201 is not None",
            {
                PHP: (
                    "$o['elapsed_ns'] = hrtime(true) - $started;\n            if ($result",
                    "$o['elapsed_ns'] = hrtime(true) - $started; $o['api']['status']=201;\n            if ($result",
                ),
                CSHARP: (
                    "case Mutation mutation:\n",
                    "case Mutation mutation:\n                    observation.api.status = 201;\n",
                ),
            },
        ),
    ]
    try:
        for title, test, expected, replacements in mutations:
            for path, (before, after) in replacements.items():
                if originals[path].count(before) != 1:
                    raise RuntimeError("mutation seam changed; inspect proof before running")
                path.write_text(originals[path].replace(before, after))
            build()  # A compile failure is infrastructure, never red.
            result = run_test(test)
            report = (result.stdout + result.stderr).decode()
            if (
                result.returncode != 1
                or "AssertionError:" not in report
                or expected not in report
                or "ERROR:" in report
            ):
                raise RuntimeError("behavioral red was not observed:\n" + report)
            if "language='php'" not in report or "language='csharp'" not in report:
                raise RuntimeError("both public CLI controls must reject the mutation:\n" + report)
            print("RED:", title, "=>", expected, flush=True)
            for path, original in originals.items():
                path.write_text(original)
    finally:
        for path, original in originals.items():
            path.write_text(original)
        build()
    for test in {case[1] for case in mutations}:
        result = run_test(test)
        if result.returncode:
            raise RuntimeError(
                "restored green failed:\n" + (result.stdout + result.stderr).decode()
            )
        print("RESTORED GREEN:", test, flush=True)


if __name__ == "__main__":
    main()
