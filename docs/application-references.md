# Application generation references

The private [reference API](../src/consensus/application_reference.h) pins an
existing application file independently of native writer ownership. The
[protection composition](../src/consensus/journal_protection.h) consumes an
immutable journal census and owns references for its decoded application edges.
These are retention prerequisites. They do not implement a retention policy or
protect every journal producer continuously.

## Lock and lifetime contract

Acquisition independently opens the native file read-only and takes a
nonblocking Linux `F_OFD_SETLK` read lock on byte zero, length one. This is
separate from the native engine's `flock` lock: the active writer can retain its
exclusive ownership while references coexist. Retained directories are also
independently reopened, so references never inherit the controller's exclusive
document-root lock.

Cloning duplicates the reference's own descriptors. The native descriptor keeps
the same open file description, so closing one clone does not release siblings'
protection. Close issues no explicit unlock and deletes nothing. References
survive caller directories, writers and controllers closing. Join all users
before close; immutable validation, information and clone calls may overlap.

Ticketed retirement opens its independent native descriptor read/write during
preparation. Before taking its existing exclusive native flock or moving any
file into custody, it takes an OFD write lock on the same byte. Reference
contention returns busy without creating custody. An acquired write lock remains
held through partial cleanup retries, including a subsequent native-flock busy
result. New reference acquisition then returns busy until that ticket completes
or closes. Existing publication authority, custody checks, pinned-reader rules,
unknown-data preservation and directory-shell handling remain applicable.

This cooperative protocol requires Linux local-filesystem semantics with OFD
locks and flock ownership remaining separate. NFS/SMB behavior and other
platforms are unqualified. Unsupported locking is an error; there is no fallback
to process-associated locks. Advisory locks do not exclude an uncooperative
filesystem actor.

## Typed application edges

Each decoded journal root supplies application identity A and snapshot boundary
B separately. Zero A requires an existing private native file in the original
document root and absence of initialization/candidate markers. Acquisition never
initializes an empty application.

Nonzero A resolves `.yamora-generations/A/`. The completed manifest must hash to
A and decode for the trusted cluster/voters. Its positive origin index/term must
not exceed B; equal indexes require equal terms and A equal to B's archive hash.
An older generation A with a later, different checkpoint B is valid. The native
file may have grown since its origin; this API does not verify the native image,
current superblocks, application graph, journal suffix or recovery acceptance.

After obtaining protection, acquisition rechecks the entire original name/inode
chain, trust, private files and marker state. Explicit validation repeats those
checks, including immutable manifest bytes, without adopting replacements.
Cloning retains the originally acquired inode even if its names later change.

## Census composition

`yd_raft_journal_protection_take` always consumes its census, including on bad
arguments or allocation failure. Only failure to allocate the outer token
returns null; other faults return owned partial information. The caller supplies
the trusted document-root relationship, which must be distinct from the journal
root. Census identity alone cannot authenticate that relationship.

The token retains at most 64 application references, one per known captured
root, with at most five descriptors each. Repeated A values do not skip any
root's A/B validation. Empty roots and invalid headers add no application edge;
unknown metadata or incomplete census coverage prevents application-pin
completeness. Archive-pin completeness remains the census's independent result.

Callbacks and filesystem work run outside controller/backend locks. The final
callback precedes every final binding check. Cancellation, missing/busy files,
I/O failure or changed bindings produce partial results while preserving every
successfully acquired reference until token close. Accessors return immutable
copies and expose no native handles or descriptors.

Completeness describes only the consumed historical census. Composition does
not refresh its producer revision, exclude new dependency creation, establish an
atomic retention barrier, reconstruct crash provenance or grant deletion
authority. Continuous producer protection, durable retention provenance and
crash-leftover reconciliation remain open.

## Verification

The focused suite uses exact native metadata frames and manifest framing,
independent lock probes, syscall faults and immutable source bindings. Its
synthetic application bytes deliberately establish no graph-validity claim.

```sh
TMPDIR=/var/tmp/andromeda-work/yamora-binary-storage \
  python3 -B -m unittest yamora.tests.test_application_reference -v
```

The default compiler profile uses fatal ASan/UBSan and leak detection. Set
`YAMORA_REFERENCE_SANITIZER=thread` for unsuppressed TSan;
`YAMORA_REFERENCE_CRYPTO_FLAGS` may select the existing instrumented OpenSSL
build. Existing real TLS retirement, custody-fault and recovery scenarios remain
in `yamora.tests.test_raft_application_retire`.
