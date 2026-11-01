# Binary TLS server transport

The transport in `src/transport/tls.h` exposes a dedicated server profile and
nonblocking server operations. This is a TLS slice: the daemon listener, runtime
bridge, bearer authentication, roles, frame processing and public SDK are outside
its scope. Qualification below is Linux only; it establishes no macOS, Windows,
production listener or end-to-end binary database qualification.

## Profile and ownership

Use `yd_tls_binary_new(certificate, key, client_ca, error, length)` or
`yd_tls_binary_new_with_options(..., &options, error, length)`. They use the same
bounded identity, key, trust and CRL loaders as HTTP. A NULL client CA permits
server-authenticated TLS; a configured CA requires a verified client certificate
with client purpose, exactly as HTTP does. The server certificate uses server
purpose, without Raft's peer identity requirement. CRL options require a CA and
retain the existing complete direct issuer CRL constraints in
[tls-revocation.md](tls-revocation.md).

All profiles require TLS 1.3. Binary requires exact ALPN `yamora-binary/1`, including
an explicit check after handshake because OpenSSL does not invoke its ALPN
selection callback for an absent offer. Offers containing other protocols may
succeed only when they also contain this exact identifier. HTTP keeps
`http/1.1` and its absent-ALPN compatibility; Raft keeps mandatory `yamora-raft/1`.
`yd_tls_is_peer` identifies only Raft; `yd_tls_is_binary` identifies only binary.

`yd_tls_reload` builds a complete replacement before publishing it under the
profile's mutex. Failure keeps the previous valid context. SSL sessions acquire
references under the same mutex and retain their old identity/trust snapshot
through reload or profile destruction. Reload may run concurrently with begin and
established I/O. Profile destruction must be serialized against begin and reload;
there must be no future begins after free. Changing CRLs affects new handshakes,
not previously authenticated connections.

Call `yd_connection_binary_begin(&connection, fd, profile)` on a fresh or closed
connection. It creates owned SSL and private connection state, enables
`O_NONBLOCK`, and performs no handshake. It does not duplicate or own the fd;
`yd_connection_close` frees binary TLS state without sending close_notify and
leaves the fd open. Begin failure frees partial allocations and leaves a failed,
close-safe connection. The caller owns socket setup, close, SIGPIPE handling and
connection lifetime. Never copy a live `YDConnection`. Its private pointer is
internal, and this source-level extension requires consumers to rebuild.

## Step contract

Exactly one I/O thread serializes each connection's steps and close. Do not mix
these APIs with the legacy blocking wrappers. The wrappers retain their existing
HTTP/Raft timeout and shutdown semantics, including the legacy write deadline
latch; the binary steps do not consult that latch.

```c
bool yd_connection_binary_begin(YDConnection *c, int fd, YDTLS *profile);
YDTLSStep yd_connection_handshake_step(YDConnection *c, uint64_t deadline);
YDTLSStep yd_connection_read_step(YDConnection *c, void *buffer, size_t size,
                                  uint64_t deadline, size_t *transferred);
YDTLSStep yd_connection_write_step(YDConnection *c, const void *buffer, size_t size,
                                   uint64_t deadline, size_t *transferred);
```

Every step receives a nonzero **absolute CLOCK_MONOTONIC deadline in
milliseconds**. Establish one deadline for an operation and preserve it through
WANT and partial progress. A subsequent request receives its own caller-selected
deadline, independent of HELLO or previous writes. A zero, elapsed deadline or
monotonic clock failure is terminal. There is no implicit fresh budget or replay.

| Result | Caller action |
| --- | --- |
| `YD_TLS_READY` | Handshake complete, or positive I/O progress in `*transferred`. |
| `YD_TLS_WANT_READ` | Arrange readability, then retry before the same deadline. |
| `YD_TLS_WANT_WRITE` | Arrange writability, then retry before the same deadline. |
| `YD_TLS_EOF` | Authenticated close_notify; sticky EOF, then close. |
| `YD_TLS_ERROR` | Sticky `c->failed`; discard TLS state, then close the caller's fd. |

Steps never poll, sleep or loop waiting for readiness. Each invokes at most one
SSL handshake/read/write operation. WANT may request the opposite direction to
the application operation. Try reading before waiting on the socket: OpenSSL can
already hold decrypted bytes after an earlier read. An unclean TCP EOF, TLS
alert, syscall failure or invalid operation returns ERROR rather than clean EOF.
`errno` distinguishes deadline expiration (`ETIMEDOUT`), invalid contracts
(`EINVAL`), ALPN rejection (`EPROTO`), snapshot allocation failure (`ENOMEM`) and
other terminal TLS/I/O/clock failures (`EIO`); WANT/EOF/READY do not define errno.

Read and write require completed handshake, non-NULL buffer/output and positive
size. The output count is cleared before validation and remains zero for all
non-READY results, including failed connections. Read buffer contents outside
the READY prefix are unspecified. EOF remains EOF on repeated calls; only close
is useful afterward. A terminal error may follow transmission, so zero reported
progress after ERROR is never proof that nothing reached the peer.

A write step snapshots the supplied bytes into owned memory. After WANT the
caller **must preserve the original pointer, full length and bytes** until that
write resolves. The implementation checks all three, retries SSL with the same
snapshot pointer/length, and rejects reads while that write is pending. Changing
the caller's buffer, substituting an equivalent allocation, shortening the span,
or interleaving a read fails the connection. Keep caller spans reasonably bounded:
the snapshot needs `size` additional bytes and comparison work is proportional
to that span. Snapshot data is cleansed and freed on progress, error, EOF or close.

After positive partial progress, advance the pointer by `*transferred`, subtract
that count from the remaining length, and submit only the suffix under the same
operation deadline. A positive prefix is not completion of an application frame.
After the entire operation succeeds, a new operation may use a new deadline.

## Focused verification

From the repository root, set TMPDIR to the active task's exact disk-backed
scratch root before running these commands. Tests allocate unique children and
remove them, including their processes, on success and failure.

```sh
python3 -m unittest yamora.tests.test_binary_tls -v
BINARY_TLS_SANITIZER=address,undefined ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 python3 -m unittest yamora.tests.test_binary_tls -v
BINARY_TLS_SANITIZER=thread BINARY_TLS_OPENSSL=/path/to/instrumented/openssl TSAN_OPTIONS=halt_on_error=1:exitcode=66 python3 -m unittest yamora.tests.test_binary_tls.BinaryTlsTests.test_native_begin_reload_overlap_retains_acquired_context yamora.tests.test_binary_tls.BinaryTlsTests.test_native_overlap_guard_rejects_serialized_begin_reload yamora.tests.test_binary_tls.BinaryTlsTests.test_concurrent_context_reload_and_serialized_connection_io -v
```

Thread qualification requires an existing fully TSan-instrumented OpenSSL prefix
containing `include`, `libssl.a` and `libcrypto.a`; it refuses a missing prefix.
The test never edits or rebuilds the supplied dependency. Sanitizers are fatal,
with no suppressions. The normal and ASan/UBSan suites include behavioral guard
mutants for absent ALPN, elapsed and stale deadlines, changed SSL retry pointers
and fd ownership. Those mutated copies must compile and fail their targeted
behavior checks; the originals must pass. Real TCP clients use Python stdlib TLS
with CA and hostname verification, independently from the native server API.
Fault wrappers additionally cover allocation, SSL setup, opposite-direction WANT,
short positive writes and syscall/shutdown outcomes. They complement real socket
backpressure and verified TLS/mTLS/CRL handshakes.

Begin/reload lifetime qualification uses a separate deterministic native test.
Link wrappers pause begin at `SSL_new` while it holds the production profile
mutex. A separate reload thread must encounter `EBUSY` on that exact mutex before
the old context reference is acquired. After acquisition, begin pauses at
`SSL_set_fd` until reload publishes the replacement and releases the previous
profile context reference. The two threads must be distinct, and all gates use
bounded monotonic condition waits. A verified TCP handshake must then present
the original certificate, while a subsequent connection presents the replacement;
both must exchange bytes after profile destruction. These hooks are test-only
and inactive outside this coordinated case.

The serialization guard compiles the harness with `YD_TEST_SERIALIZE_OVERLAP`
to invoke begin/reload sequentially. The targeted lifetime test must fail with
the specific native overlap-gate diagnostic, rather than a compilation error.
Both the coordinated test and this negative control run under unsuppressed TSan
with the instrumented OpenSSL. The earlier connection-I/O concurrency test is
preserved, but its main-thread begins are serialized against reload dispatch;
that test alone does not establish begin/reload overlap.

The targeted shared-transport regressions are `yamora.tests.test_tls` (12),
`yamora.tests.test_raft_rpc` (15), `yamora.tests.test_tls_revocation` (18) and
`yamora.tests.test_tls_revocation_daemon` (5). TLS/daemon tests need a freshly built
native daemon supplied through `YAMLDB_BUILD_DIR`. No repository-wide suite is
needed for this slice; the parent owns combined wiring and acceptance.
