# Local Python package artifacts

The canonical Python project remains `yamora` **0.3.0**, Python 3.10+, with
the existing setuptools backend. This local packaging foundation publishes
nothing to a registry and bundles no native daemon.

Run the builder with a fresh output directory outside the checkout:

```sh
python3 yamora/drivers/python/build_package.py --output /absolute/private/artifacts
```

The build interpreter needs the existing `setuptools>=77` build requirement.
The qualified interpreter used setuptools 83.0.0. The builder uses that backend
directly, stages only [explicit inputs](../drivers/python/package-files.json)
in a private workspace below the stable task scratch root selected by TMPDIR
(`/var/tmp/andromeda-work/<task>`). Nested caller allocations do not own that
workspace. The existing repository process supervisor owns a separate process
group, disk-backed log and finite TERM/KILL teardown on success, failure,
timeout or Python interruption. Staging and backend outputs are removed only
after verified group shutdown; unverified shutdown retains the workspace and
its `.yamora-sdk-retained-*` guard. Stop and verify the recorded owned processes
before reconciling that retained allocation. Artifacts are copied to the
requested output only after verified stop. The builder imports repository
tooling, which is excluded from artifact runtime contents. It generates a wheel
and source distribution. The extracted sdist
contains its own pyproject, sources, README, example and exact MIT license; it
rebuilds without the original checkout. Metadata, version, extras and entry
points come from [the existing project](../pyproject.toml).

The artifacts retain all public HTTP, cluster and binary transport modules,
plus administration modules and the `yamldb` compatibility namespace.
`yamldb.client.YamoraClient` remains the canonical client class. Native C files,
GitOps, tests, seed documents and the website's schema registry are excluded.
Installing the base wheel adds no runtime dependencies. Administration retains
the existing `admin` extra and PyYAML requirement; both `yamoractl` and
`yamldbctl` require that extra, including their help command. Supply your own
`--schema` for application validation/import and the existing `--binary` option
for native restore. The daemon and native capacity fallback are separate
installation prerequisites; packaging does not change their lookup semantics.

## Installed public TLS example

Create a private virtual environment and install the local wheel:

```sh
python3 -m venv /absolute/private/consumer
/absolute/private/consumer/bin/python -m pip install --no-deps /absolute/private/artifacts/yamora-0.3.0-py3-none-any.whl
/absolute/private/consumer/bin/python -I /absolute/private/consumer/share/doc/yamora/examples/crud_tls.py --port 8765 --ca /private/ca.pem --cert /private/client.pem --key /private/client.key --read-token-file /private/read-token --write-token-file /private/write-token
```

Use a disposable standalone native database with verified HTTPS, optional
mTLS identity and private token files. The example defaults to numeric loopback;
`--host` selects an explicitly configured private IPv4 endpoint. It creates
`packaged/python-example`, verifies exact UTF-8 YAML including CRLF/comments,
updates with an ETag, proves stale rejection, and deletes with the current ETag.
Choose `--collection`/`--document` for a fresh test document. It never retries
an uncertain mutation or prints credentials/source/error bodies. A failure
can leave its test document behind; reconcile before explicitly rerunning.

The installed wheel also provides `yamora.binary_client` and its public
configuration, response and error types. Packaging changes neither TLS nor
request/recovery semantics. See [binary client behavior](python-binary.md).

## Focused acceptance

The test module is `yamora.tests.test_python_package`. Supply an absolute
`YAMORA_TEST_BINARY` naming the immutable fatal-ASAN/UBSAN daemon and
`YAMORA_PACKAGE_WHEELHOUSE` containing the existing optional PyYAML wheel.
Tests never download dependencies or skip missing prerequisites.

```sh
python3 -m unittest yamora.tests.test_python_package -v
```

Lifecycle tests first witness a real advancing descendant with captures closed,
then check success, failure, timeout and interruption teardown. Injected stop
uncertainty must retain staging and its guard outside the caller's disposable
allocation. These fixtures stop their own processes before removing retained
test files.

Tests audit wheel and sdist contents/license/metadata, install in private
consumers, require all runtime imports to originate inside those consumers,
check dependency-free imports and CLI aliases separately, rebuild the sdist
outside the checkout, and execute the shipped example with real native mTLS.
Wrong CA trust and stale ETags must reject after valid controls. The daemon
digest is checked before/after and owned processes/allocations are cleaned.

Use the parent-approved managed task runner. Its filesystem overlay and tools
are ephemeral: private prerequisite provisioning and tests must share one
runner invocation, or receive already visible tool/artifact inputs.

This qualifies local Linux artifacts and the public CRUD example. Both shared
conformance profiles still need parent-owned artifact adapter wiring and runs
against installed consumers with the SDK checkout excluded. Examples do not
close that broader gate. Registry release and other platform qualification
remain separate work.
