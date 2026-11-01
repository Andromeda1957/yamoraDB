# Native Windows SDK qualification

Windows client execution has bounded evidence on the owner's `.129` machine,
Windows 10 x64 build 19045. WSL1 provides authenticated SSH access; the tested
interpreters, JVM, Go executables and .NET processes run natively on Windows.
The server remains a separate Linux native Yamora daemon. These results do not
qualify a native Windows daemon, Windows 11, macOS or complete SDK portability.

The owner authorized this Windows testing on 2026-10-26, superseding the earlier
Windows-machine exclusion for this task. The macOS exclusion remains in place.
The tested source is committed snapshot `d904a7769`; subsequent integration
changes require their own affected-path verification.

## Observed coverage

| SDK and native runtime | Result | Boundary |
| --- | --- | --- |
| Java, JDK 19.0.1 | All 12 targeted binary checks pass | Source-compiled public adapters; installed JAR and full conformance remain unqualified on Windows |
| Node, 22.23.1 | All 12 targeted binary checks pass | Public source adapters; TypeScript/package installation, cancellation and full conformance remain unqualified |
| Go, 1.27.3 windows/amd64 | Public HTTPS CRUD example passes | Exact source, conditional replacement, stale-write refusal and deletion; binary adapters do not compile on Windows |
| Ruby, 4.0.9 x64-mingw-ucrt | Public HTTPS CRUD example passes | Source library and example; installed gem, binary operations and full conformance remain unqualified |
| PHP, 8.5.12 NTS Visual C++ 2022 x64 | Public HTTPS CRUD example passes | Source HTTP library with an explicit local bootstrap; Composer package and binary clients remain unsupported on Windows |
| Python, 3.14.4 win32 | All 12 targeted binary checks fail during TLS configuration | Linux-only identity loading; authenticated HTTP construction also fails on a missing OS constant |
| C#, SDK 10.0.403 | Local NuGet pack/restore/build succeeds; installed HTTPS example fails | Windows 10 TLS limitation and Linux-only binary adapters prevent qualification |
| Rust | Not executed; native compiler unavailable | Cancellable connection implementation explicitly refuses non-Linux targets |
| C++ | Not executed; native compiler unavailable | Transport depends on POSIX networking headers and calls |

The twelve binary checks cover document creation, exact-source reads, HEAD,
read-credential write denial, missing/wrong credentials, stale-write refusal,
query, aggregation, PATCH, read-credential PATCH denial and missing operation
credentials. Mutations and denials have independent native HTTPS source checks;
query and aggregation results are compared with the native HTTPS API.

Node intentionally omits a numeric status from successful document replies.
Three initial probe assertions incorrectly required that field. Corrected checks
use its documented success, receipt, body and representation-length values plus
native source witnesses; those three checks pass. The nine unaffected passes are
retained. This was a probe correction, not a Node SDK repair.

## Portability blockers

- Python's [binary TLS loader](../binary_client.py) uses `os.memfd_create`,
  `os.MFD_CLOEXEC` and `/proc/self/fd` for client identities. Native Windows lacks
  those APIs, producing `BinaryError: invalid owned TLS material` before dispatch.
  Native create, read and HEAD diagnostics reproduce the same configuration
  failure. The [HTTP client's token reader](../client.py) independently uses
  `os.O_NONBLOCK`, which is also absent on Windows and raises `AttributeError`.
- Go's [document adapter](../drivers/go/conformance/main.go) does not compile:
  `syscall.FdSet` and `syscall.Select` are undefined. The operation adapter uses
  the same Unix control mechanism. This does not negate the passing native
  Windows HTTPS client example.
- C#'s [document adapter](../drivers/csharp/conformance/Program.cs) and operation
  adapter explicitly require Linux and use native libc control operations. Their
  twelve execution failures establish an adapter boundary, not twelve independent
  SDK defects. The unmodified installed HTTPS example separately fails; a
  diagnostic copy changing only error reporting exposes `Yamora.TransportError`.
  Both SDK transports require TLS 1.3. Microsoft's [Schannel support table](https://learn.microsoft.com/en-us/windows/win32/secauthn/protocols-in-tls-ssl--schannel-ssp-)
  establishes that Windows 10 does not support TLS 1.3; support starts with
  Windows 11/Server 2022. That is a platform blocker, while the SDK deliberately
  redacts the lower-level transport exception. Windows 11 execution is unverified.
- PHP's [binary TLS configuration](../drivers/php/src/BinaryTls.php) explicitly
  requires Linux and POSIX UID checks. Its Composer manifest requires
  `ext-posix`; the passing source HTTP example does not establish installable
  Windows package support. Ruby's binary adapters also use Unix path assumptions;
  they were not used to claim binary coverage.
- Rust's [connection implementation](../drivers/rust/src/socket.rs) returns a
  non-Linux rejection. C++'s [HTTP transport](../drivers/cpp/src/client.cpp) and
  binary transport use POSIX socket, poll and descriptor APIs. These are inspected
  limitations; neither SDK was compiled or executed on Windows in this pass.

## Isolation and limits

The exact Linux candidate was built with the qualified Clang route in the managed
task container, then served synthetic native storage through task-owned loopback
ports and authenticated SSH reverse forwards. TLS 1.3, server verification and
mutual TLS stayed enabled. Port 8000 and shared/production databases were unused.
Portable Windows runtimes came from checksum-verified official Go, Node,
Microsoft .NET, PHP and RubyInstaller releases; no system runtime installation
was needed. Each Windows process owned a temporary directory and removed it
after its children exited. Linux fixtures, forwards and daemon processes also
closed normally.

These are focused public-API checks, not the Linux installed-artifact matrix or
the complete three frozen conformance profiles. Replica failover/receipt recovery,
streaming, cancellation/deadlines, interrupted writes, all public examples,
numeric-type parity and signed/registry distributions remain unqualified on
Windows. Passing source execution must not be relabeled as installed-package or
general Windows support.
