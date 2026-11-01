# Pure policy catalog codec v1

This module creates, parses, transforms and encodes immutable owned catalog
snapshots. It is an independent leaf: it does not compile schema sources, activate
policies, persist data, authorize callers, enforce admission, or participate in
request replay, replication or consensus. The profile barrier, activation and
enforcement remain open parent integration work. These names do not claim JSON
Schema, OpenAPI or CRD compliance.

## API and ownership

`src/schema/policy_catalog.h` is the public C17 interface. `YDPolicyCatalog` is
opaque. `empty`, `parse` and `change` return a newly allocated snapshot through
`YDPolicyCatalog **out`. `free(NULL)` is valid. There is no retain operation or
hidden reference count. Each snapshot owns all collection and source bytes;
input buffers and predecessor snapshots may be released after success.

`info` copies generation, entry count, decoded source total, canonical encoded
size, actual owned allocation size and the 32-byte catalog hash. `at` enumerates
entries in ASCII collection order; `find` performs exact name lookup. Entry
views borrow collection and source spans until the catalog is freed. The profile
pointer denotes a static literal; hash arrays are copied into the view. Preserve
the catalog lifetime across readers. Concurrent readers may call all accessors
and `encode`, with independent output buffers and budgets. The module has no
global mutable state, cache or lazy initialization of catalog fields.

`encode` writes exactly `info.encoded_bytes`, including its final LF, into a
caller-owned buffer. It appends no NUL. Query `info` first. A failed encode writes
no buffer bytes and sets `*written = 0`. Constructing calls set `*out = NULL` on
failure. Accessors clear their output structures before reporting failure.
Output arguments must not alias the catalog, input spans, other arguments, or
each other. Inputs must remain readable and stable for the entire call; passing
freed, concurrently modified or fabricated catalog pointers is outside the API.

Budget and output pointers are required. Error pointers are optional. An error
has a 160-byte NUL-terminated message and a byte offset into encoded input, or
`SIZE_MAX` when not tied to an input token. Messages contain fixed explanatory
text, never submitted content. Offsets may identify the token boundary after
an error; digest mismatches have no source offset. `errno` is not part of the
contract.

| Result | Meaning |
| --- | --- |
| `YD_PC_OK` | Complete result returned. |
| `YD_PC_NOT_FOUND` | Missing lookup/index or disable target. |
| `YD_PC_INVALID` | Malformed envelope, unknown/duplicate/missing field, duplicate collection, bad name/source/digest or version invariant. |
| `YD_PC_UNSUPPORTED` | Unknown size profile, format, schema profile, mode or operation; input/canonical output does not fit the explicitly selected profile. |
| `YD_PC_LIMIT` | Intrinsic bounds, work/allocation/capacity exhaustion or exhausted generation. |
| `YD_PC_CONFLICT` | Any CAS guard mismatch, or already-disabled policy. |
| `YD_PC_ERROR` | Missing required API argument or allocation/cryptographic provider failure. |

Error ordering is local: argument/profile/operation/name/individual size checks
precede charging; change guard comparison precedes source validation and state
checks; parse validates the entire envelope before allocating and checking
hashes. Callers must not depend on which defect wins for multiply invalid input.

## Envelope and exact source bytes

The accepted envelope is a schema-specific JSON flow subset of YAML, not a
general YAML parser. No `YDValue`, shape API or libyaml dependency is involved.
The canonical form has these keys in this order:

```json
{"format":"yamora-policy-catalog-v1","generation":"0000000000000001","policies":[{"collection":"a","version":"0000000000000001","mode":"enforce","profile":"yamora-shape-v1","source":"type: object\u000d\u000a","source_sha256":"5b526d02514ecdc9f48c4a2ecd40b573ebc34485505c8de7177194ce6d48a311","policy_sha256":"f0b4bdcc5327e6b63250d6da76308e755e210f03ea99e4f05dbce9caf2095e01"}]}
```

Canonical encoding sorts policies by collection, emits ASCII without whitespace
between tokens and ends with exactly one LF. Counters are double-quoted,
exactly sixteen lowercase hexadecimal digits; hashes are double-quoted,
exactly sixty-four lowercase hexadecimal digits. Metadata keys and values
are literal quoted ASCII without escapes. Collections have 1–128 bytes drawn
from `[a-z0-9-]`, excluding the native reserved name `yamldb-system`.

Parsing permits arbitrary field/entry order and JSON whitespace (space, TAB,
CR, LF). It rejects unknown/duplicate/missing keys, duplicate collections,
outer BOM, comments, document directives/separators, tags/anchors/aliases,
plain or single-quoted scalars, numbers/null, wrong containers, trailing commas
and trailing content. Metadata keys have at most 31 bytes; variable metadata
values have at most 128. Unknown values within those lexical bounds are
unsupported; exceeding those bounds is invalid syntax for this envelope.

`source` is a nonempty opaque UTF-8 string. It is not parsed as a schema or even
as YAML: malformed schema/YAML text may be cataloged. Source string syntax
accepts standard JSON escapes, case-insensitive hex in `\uXXXX`, and valid
surrogate pairs. Decode only the envelope quoting. Preserve every decoded
source byte, including CRLF, comments, whitespace and inner U+FEFF. Reject
invalid/overlong UTF-8, unpaired surrogates, values above U+10FFFF, NUL, C0
controls except TAB/LF/CR, U+007F–U+009F, U+FFFE and U+FFFF. This is the native
safe source codepoint profile, not a claim about every Unicode noncharacter.
Literal control bytes inside a quoted source are invalid JSON syntax.

Canonical source quoting emits printable ASCII directly except `"` and `\`,
which use two-byte escapes. `/` is literal. All other codepoints use lowercase
six-byte `\uXXXX` escapes, including TAB/LF/CR, with two escapes for non-BMP
characters. Original envelope bytes/quoting are not retained; decoded source
bytes are retained exactly and hashed without normalization.

## Bounds and explicit profiles

The per-entry schema profile is one of `yamora-shape-v1`,
`yamora-json-schema-2020-12-v1`, `yamora-openapi-3.1-schema-v1`, or
`yamora-crd-v1-schema-v1`. The latter three use the explicit source envelopes in
[the assertion contract](schema-shape-v1.md#durable-document-and-extraction-profiles).
`YDPCChange.schema_profile == NULL` preserves the original shape-v1 caller
contract. DISABLE requires NULL and retains the stored profile. The codec checks
known identities and source/hash integrity; policy admission separately compiles
and validates the selected source semantics. The existing format and hash
framing stay unchanged, including every shape-v1 golden vector.

| Resource | Inclusive bound |
| --- | ---: |
| Entries, including tombstones | 64 |
| Decoded source per entry | 32,768 bytes |
| Aggregate decoded sources, including tombstones | 2,097,152 bytes |
| Ordinary encoded input and canonical output | 262,144 bytes each |
| Large encoded input and canonical output | 16,777,216 bytes each |

The aggregate bound equals 64 times the individual bound. Input whitespace
also counts. Every constructing/encoding call requires an explicit
`YD_PC_ORDINARY` or `YD_PC_LARGE`; snapshots do not have a hidden size profile.
Exceeding an intrinsic bound returns `LIMIT`. A catalog intrinsically valid
under large but exceeding the selected ordinary profile returns `UNSUPPORTED`,
including when short input escapes expand beyond the ordinary canonical bound.
There is no automatic upgrade, disk-profile change or promise that the current
daemon can store these catalogs. Future integration must enforce its actual
storage profile barrier separately.

The maximum canonical envelope is **12,608,467 bytes**:
`6 * 2,097,152 + 25,555`. The maximum uses 64 enforcing entries with 128-byte
names and all one-byte source controls escaped sixfold. There is 4,168,749 bytes
of headroom below 16 MiB. One such maximum entry is 197,089 bytes and fits the
ordinary profile; two do not. Therefore 16 MiB bounds the entire envelope, not
just raw source. Tombstones retain the same source bounds.

## Versions, guards and tombstones

An empty catalog has generation zero. Every nonempty catalog has positive
generation and positive entry versions no greater than generation; its maximum
entry version equals generation. Versions use the full unsigned 64-bit range,
never floating point.

`YDPCChange` contains the exact collection span, operation, optional source
span and expected `(generation, catalog_sha256, target_version)`. The target
version is zero only when absent. All three guard components must match the
supplied base snapshot. `SET` creates, replaces or reactivates an entry using
`yamora-shape-v1` in enforce mode; identical source still advances the epoch.
`DISABLE` requires an existing enforcing entry and NULL source with length zero.
It retains source/profile/source hash and records off mode as a tombstone.
Disabling an absent policy is `NOT_FOUND`; disabling an off policy is `CONFLICT`.

Each successful change increments generation and assigns that generation as the
changed entry's version. At `UINT64_MAX`, changes return `LIMIT`; no wrap,
reuse, purge, reset or tombstone deletion operation exists. Failure leaves the
base snapshot intact and returns no candidate. A candidate deeply copies all
retained sources, so predecessor release cannot invalidate it.

This is CAS against a supplied immutable value, not a durable or globally atomic
commit. Parsing verifies internal invariants and hashes, not historical
provenance or rollback protection. Future authorization, atomic persistence,
activation and replay must supply those guarantees without changing this claim.

## Hash identity and vectors

SHA-256 uses raw bytes; domains are exactly eight ASCII bytes, with no NUL.
Every length/counter below is unsigned **LE64**. Mode is one byte: off = 0,
enforce = 1. Profiles and collection names use their exact ASCII bytes.

```text
source = SHA256(decoded_source)
policy = SHA256("YDPOL001" || LE64(name_length) || name
                || LE64(profile_length) || profile || U8(mode)
                || LE64(source_length) || decoded_source)
catalog = SHA256("YDCAT001" || LE64(generation) || LE64(count)
                 || for each sorted entry:
                    LE64(name_length) || name || LE64(version) || policy_hash32)
```

Policy identity excludes its version; catalog identity includes versions and
generation. Both declared entry hashes are recomputed and verified on parse.
The catalog hash is derived, not a serialized field. Hash equality is content
identity, not authorization or an authenticity signature.

Vectors use name `a`, profile `yamora-shape-v1`, and fourteen source bytes
`747970653a206f626a6563740d0a` (`type: object` followed by CRLF):

| Vector | SHA-256 hex |
| --- | --- |
| Source | `5b526d02514ecdc9f48c4a2ecd40b573ebc34485505c8de7177194ce6d48a311` |
| Empty catalog g0 | `9673bdd85106866bac56becab0d3c2e83c08b602221ee9c87f704c495ef18b80` |
| Enforce policy | `f0b4bdcc5327e6b63250d6da76308e755e210f03ea99e4f05dbce9caf2095e01` |
| Enforce catalog g1/v1 | `8741df15e087e878e4ed1208478c746094754ecec5fdbf5fce4b24956ffa3d6f` |
| Off policy | `6d2183326905d6f5ad6fe585af5a9a9eed625d671a83e0fd926b912e8f68864b` |
| Off catalog g2/v2 | `0b946303721acf18e1ef73901be23fa899e15b77c19ecc77140f3e2ddc7349d7` |
| Enforce g/v `0102030405060708` | `9ef62094049edcf38237193642cd9141eb9e7d83c7284620b013112c1edcbd1a` |
| Enforce g/v `ffffffffffffffff` | `3c244c4368b5eb9c69a6a218f5386d3919c6f087f6891fe9e81d0993bfad1778` |

LE64(`0102030405060708`) is `08 07 06 05 04 03 02 01`.

## Work, allocation and parser temporary memory

`YDPCBudget.work_left` is a caller-shared unsigned counter. Successful reservation
subtracts the entire charge before variable work; no refunds occur after error.
Insufficient work sets the remaining counter to zero and returns `LIMIT`.
Fixed lexical/profile/argument checks may fail before charging. It is an explicit
accounting unit, not a wall-clock instruction guarantee.

| Call | Reservation |
| --- | ---: |
| `empty` | 1,024 |
| `parse` | 1,048,576 + 16 × encoded input bytes |
| `change` | 1,048,576 + 16 × (base decoded source total + supplied source bytes) |
| `encode` | 1,024 + canonical encoded bytes |

Accessors/free have no budget. Callers must serialize use of a shared budget
or provide separate budgets for concurrent calls.

`allocation_limit` bounds the peak new **module-owned heap bytes per call**,
including the returned object. It excludes preexisting snapshots, caller buffers
and OpenSSL allocations. Zero allows no new owned allocation; encode allocates
none. An object uses one `malloc`: a fixed 64-entry header and a contiguous
decoded-source blob with one extra NUL per entry. `info.owned_bytes` is the
actual requested malloc size, not allocator overhead. Owned overhead beyond
decoded sources is at most 32,768 bytes, compile-time checked.

The parser scans the borrowed encoded input into a fixed stack descriptor array,
validates limits/duplicates/version invariants, allocates once, then decodes
sources directly into their final owned storage and verifies hashes. It creates
no general YAML/JSON AST, encoded-input copy or temporary whole-source buffer.
Module automatic storage remains below 65,536 bytes (fixed descriptors plus
small scan/hash locals; no recursion). Caller input (up to 16 MiB), canonical
output (up to 12,608,467 bytes), old snapshots and runtime allocator overhead
must be budgeted separately. Encoding itself uses only fixed scratch bytes.

OpenSSL is an existing native dependency. Each constructing call creates one
digest context and reuses it; provider/context allocations are deliberately
outside `allocation_limit`. This is not a total RSS or provider-memory cap.
Provider/allocation failures free the candidate and return `ERROR`.

## Focused acceptance

`tests/test_schema_policy_catalog.py` compiles the actual C codec and standalone
native harness with clang, OpenSSL, pthreads, fatal ASAN/UBSAN and no shape or
daemon sources. Its first positive empty-catalog assertion was observed failing
against a compilable `ERROR` stub before implementation. Fixtures use independent
Python SHA-256 and explicit little-endian serialization. Native checks cover
ownership, tombstones, guards, exact budgets, atomic outputs and injected module
allocation/provider failures. Parser cases exercise strict syntax, hashes,
Unicode, version extrema, 64-entry limits, full 2 MiB source/12,608,467-byte
encoding and both explicit profiles. Guard mutants must compile and fail at their
specific assertion; sanitizer crashes do not count as mutant detection.

Run only through the parent-selected managed task environment:

```sh
python3 /home/andro/projects/andromeda/website/agent/task_environment.py --repository /home/andro/projects/andromeda/website-agent-yamora-binary-storage run --task yamora-binary-storage -- env YD_PC_TSAN=1 /usr/bin/python3 -m unittest yamora.tests.test_schema_policy_catalog
```

The ordinary native `make test` gate sets `YD_PC_TSAN=1` and requires the focused
immutable-reader TSAN test. Direct module runs must set it explicitly, as above.
Failure to initialize TSAN fails that check and leaves an unverified TSAN
outcome, never evidence that the catalog is race-free. No daemon acceptance,
disk recovery, admission or consensus behavior is claimed by this leaf.
