# Offline JWT access tokens

Native HTTP access-policy version 3 validates typed RS256 access tokens using
C17 and system OpenSSL 3. Exact subject/client mappings select existing local
collection roles. Operators supply a curated local public JWKS file. There is
no issuer discovery, network key fetch, introspection, token acquisition,
refresh, replay cache or browser sign-in. Provider compatibility is unqualified.

Binary requests retain static-token and certificate authentication; they cannot
enter OIDC verification. Static credential files remain capped at 512 bytes.
No external database engine or runtime package is added.

## HTTP configuration

Use `--access-policy-file` with native storage, the administrative read
credential and server TLS certificate/key. Writes still require the
administrative write credential. Certificate principals additionally require an
explicit client CA. Invalid configuration fails before storage opens.

```yaml
version: 3
oidc:
  issuer: "https://issuer.example/tenant"
  audience: "urn:yamora:production"
  jwks_file: /run/credentials/yamora/issuer-jwks.json
  algorithm: RS256
  required_scope: yamora.access
  clock_skew_seconds: 30
  max_token_lifetime_seconds: 900
roles:
  manifest-editor:
    read: [manifests]
    write: [manifests]
principals:
  deployment-agent:
    oidc:
      subject: operator-supplied-stable-subject
      client_id: operator-supplied-client-id
    roles: [manifest-editor]
```

Version 3 has exactly four root fields and all seven shown OIDC fields. Require
at least one OIDC principal. Every principal has `roles` plus exactly one of
`token_file`, `tls_client_sha256` or `oidc`. An OIDC mapping has exactly `subject`
and `client_id`: unique pairs of nonempty strings, at most 255 UTF-8 bytes each.
Versions 1/2 retain their strict schemas. External roles, groups or email never
assign local grants. Audience identifies this resource, separately from client ID.

The JWKS path is absolute and at most 4,096 bytes. Bounded private-file loading
rejects final symlinks, nonregular, insecure and oversized files under the
existing operator-controlled directory assumptions. Curate the public-key
profile below rather than installing an arbitrary discovery response. Existing
[policy, role and principal bounds](access-control.md) still apply.

HTTP retains its 8,192-byte total header limit. With OIDC enabled, Bearer tokens
may contain up to 4,096 bytes. Duplicate/oversized Authorization retains the
existing transport rejection. Keys and mappings remain immutable until restart;
SIGHUP reloads TLS only. Correct synchronized wall-clock time remains an
operator responsibility. See the rotation procedure below.

## Native interface and ownership

[oidc.h](../src/security/oidc.h) defines the complete public interface:

- `yd_oidc_new(options, jwks, length, error, error_length)` copies configuration
  and imports public keys into immutable owned state. NULL means invalid
  configuration/key material or local setup failure. Diagnostics are fixed
  generic messages and contain no supplied values.
- `yd_oidc_verify(oidc, jwt, length, now_seconds, out)` authenticates a bounded
  credential. It reads trusted Unix wall-clock seconds supplied by native code.
  It never reads a clock or makes a policy/grant decision.
- `yd_oidc_free(oidc)` is NULL-safe. The caller excludes destruction from
  concurrent verification. Verification contexts and parsed documents are
  private to each invocation; readers may share the immutable object.

`YDOIDCOptions` contains `issuer`, `audience`, `required_scope`,
`clock_skew_seconds` and `max_token_lifetime_seconds`. Strings must be
NUL-terminated. All input buffers and the output object are explicitly disjoint.

On VALID, `YDOIDCIdentity` owns copies of `subject[256]`, `client_id[256]`,
`expires_at` and `required_scope_present`. These copies do not borrow parser,
token, key-set or options buffers. Expiry is the signed `exp` value, before
skew adjustment.

| Result | Meaning |
| --- | --- |
| `YD_OIDC_VALID = 1` | Signature and identity/time claims passed. The parent must still check the scope flag and map the exact issuer/subject/client tuple to local roles. |
| `YD_OIDC_INVALID = 0` | Credential rejected: syntax, bounds, unsupported profile, key selection, claims, time or invalid signature. |
| `YD_OIDC_ERROR = -1` | Invalid caller arguments/time or local allocation/provider/verification-operation failure. |

Every non-VALID result clears all bytes of a non-NULL output. Both failure
statuses fail closed. Missing required scope produces VALID with a false scope
flag; the parent maps that to its existing forbidden decision, never a grant.
External `roles`, `groups`, email and other extra claims cannot assign rights.

## Accepted profile and limits

These bounds are deliberate restrictions of this slice.

| Input | Accepted bound |
| --- | --- |
| Compact JWT | 4,096 bytes, exactly three nonempty unpadded base64url segments |
| Decoded protected header / claims / signature | 512 / 2,048 / 512 bytes |
| JWKS | 65,536 bytes; exactly one root `keys` array with 1–8 keys |
| JSON documents | Eight container levels; 256 value nodes for JWTs and 4,096 for JWKS |
| Subject, client ID, JTI | Nonempty strings, at most 255 UTF-8 bytes, no ASCII controls or DEL |
| Issuer | Nonempty visible ASCII HTTPS identifier, at most 512 bytes; nonempty authority, no userinfo, query, fragment or backslash |
| Configured audience | Nonempty visible ASCII identifier, at most 256 bytes |
| Configured scope | One OAuth scope word, at most 128 bytes |
| Scope claim | Optional string, at most 1,024 bytes; single spaces separate scope words |
| Clock skew / token lifetime | 0–120 / 60–3,600 seconds |
| Caller time / NumericDates | Integral seconds from 0 through 253402300799 |

Audience is a string or an array of 1–8 unique, nonempty strings of at most
256 bytes. One must exactly equal the configured resource audience. It is
separate from `client_id`. Issuer comparison is exact, without case folding,
URL rewriting or Unicode normalization. Subject and client ID are copied
exactly for the parent's tuple lookup.

Require `iss`, `sub`, `aud`, `exp`, `iat`, `jti` and `client_id`.
The protected header contains exactly `alg`, `kid` and `typ`.
Algorithm is exactly RS256. Type is the access-token media type `at+jwt`
or `application/at+jwt`, compared case-insensitively as a media type.
This access-token profile follows
[RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.html#section-2), with the
additional local bounds above. ID tokens are rejected.

Reject embedded keys, key URLs, critical extensions, unencoded payloads,
compression, nested/encrypted forms and extra protected header fields.
Reject `cnf` tokens because this slice cannot enforce their proof binding.
Unknown payload claims are fully parsed and bounded before their meaning
is ignored.

The module-private [oidc_json.h](../src/security/oidc_json.h) parser accepts
strict JSON rather than the document engine's YAML language. It rejects
duplicate member names after escape decoding, invalid UTF-8, unpaired
surrogates, decoded NUL, comments, trailing data/commas and non-JSON numbers.
Numbers used as dates must be integral digit spellings; fractions, exponents,
strings, booleans and overflow are rejected. The JSON document owns its nodes
and decoded strings. Input size, node count and nesting are bounded before
unbounded allocation can occur. These restrictions are consistent with the
implementation limits permitted by
[RFC 8259](https://www.rfc-editor.org/rfc/rfc8259.html#section-9).

Base64url is canonical: no padding, whitespace, non-URL alphabet, impossible
lengths or nonzero unused bits. Signature verification uses the original encoded
`header.payload` bytes, following
[JWS compact serialization](https://www.rfc-editor.org/rfc/rfc7515.html#section-3.1).

For caller time N, skew S and lifetime limit L, require:

```text
iat < exp
exp - iat <= L
iat <= N + S
N < exp + S
if nbf exists: nbf < exp and nbf <= N + S
```

Range checks make these operations fit signed 64-bit arithmetic. The parent
must supply a functioning, synchronized wall clock; successful clock reads
cannot establish that the clock is accurate. Expiration/not-before meanings and
small skew allowances come from
[JWT registered claims](https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1).

## Pinned public keys and signature results

Each curated JWK requires `kty: RSA`, `alg: RS256`, a unique printable ASCII
`kid` of 1–128 bytes, canonical unsigned `n` and `e`. Moduli are 2,048–4,096
bits; exponent is 65537. Optional `use` must be `sig`; optional `key_ops`
must be exactly `[verify]`. Reject unsupported fields, private/symmetric
material, duplicate IDs and an invalid member anywhere in the set. A provider's
unfiltered key-set response is not this curated profile.

Keys are imported with `BN_bin2bn`, `OSSL_PARAM_BLD` and
`EVP_PKEY_fromdata(..., EVP_PKEY_PUBLIC_KEY, ...)`; public-key validation and
SHA-256/PKCS#1 verification setup are checked during construction. Each key is
bound to RS256 rather than selected by an untrusted algorithm request. This
implements the algorithm-binding rule in
[RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.1), using
[OpenSSL public-key import](https://docs.openssl.org/3.0/man3/EVP_PKEY_fromdata/)
and [JWA RSA parameters](https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3).

Before cryptography, wrong signature width or a representative greater than or
equal to the modulus returns INVALID. Verification uses SHA-256 and explicit
`RSA_PKCS1_PADDING`. `EVP_DigestVerify` result 1 authenticates; result zero
returns INVALID even when the OpenSSL error queue contains padding errors.
Negative results and setup/allocation failures return ERROR. The error queue
is not used to turn an invalid signature into an operational error.
[OpenSSL verification return values](https://docs.openssl.org/3.0/man3/EVP_DigestVerifyInit/#return-values)
document the distinction; both rejecting statuses remain closed.

The loaded object never changes when its source buffers or files change.
Unknown `kid` is INVALID and triggers no fetch. To rotate, the parent/operator
loads old and new IDs together, switches signing after all serving nodes trust
the new key, then removes the old key after the token lifetime plus skew.
Policy/key replacement requires the parent's controlled restart; SIGHUP remains
TLS-only. Offline validation cannot observe issuer-side revocation. The separate
[identity adapters](identity-providers.md) supply bounded discovery, online
introspection/revocation, a distinct nonce-bound ID-token profile, IAM, LDAPS and
system Kerberos entrypoints. A parent must explicitly integrate them; their
presence does not change this offline access-token mode. Real Google/AWS,
enterprise provider and browser-login compatibility remains unqualified.

## Dispatch boundary

Select matched static credentials, including wrong-mode administrative
credentials, before considering OIDC. Explicit Authorization remains exclusive;
never combine or fall back to certificate grants. Only native HTTP-origin
requests may enter this verifier. Binary requests never enter the JWT verifier.

Check scope, map one local principal and reuse the existing collection grant
evaluator. Revalidate during large-body admission and immediately before storage
or cluster dispatch, including before receipt replay. Do not cache a principal
on a connection. Keep full transaction and foreign-lookup checks before
storage preparation.

HTTP response mapping is INVALID/unmapped to 401, valid mapped but
insufficient scope/grants to 403, and ERROR to 503. Preserve generic bodies,
revision metadata and existing transport errors. Grant/token expiry after
dispatch does not roll back an operation. Lost replies retain the existing
uncertain-write contract; no retry or replay guarantee is added.

## Focused verification

Run inside the repository's managed rootless task environment, with its existing
owned disk-backed TMPDIR and installed Clang/OpenSSL dependencies:

```sh
python3 -m unittest yamora.tests.test_oidc -v
```

The suite builds only [oidc_harness.c](../tests/oidc_harness.c), this verifier
and its parser. It does not build or run a daemon. All RSA private keys are
generated synthetically inside a unique temporary allocation and removed on
success or failure. Missing tools and compilation failures fail the suite.
The default `OIDC_SANITIZER=address,undefined` enables fatal ASan/UBSan;
`CC` selects an existing compiler. No installation or host fallback is used.

Positive controls include 2,048/4,096-bit signatures, copied configuration,
six concurrent readers, exact JWT/JWKS size limits, scope evidence and date
boundaries. Negative controls include invalid RSA/PSS signatures, algorithm/type
confusion, claim binding, duplicate/escaped JSON names, invalid UTF-8, quotas,
key rotation ambiguity and local failures. Link wrappers inject allocation,
context/setup and zero/negative verification results only in the harness.

`OIDC_SOURCE` and `OIDC_JSON_SOURCE` select trusted isolated source copies for
guard-removal controls; `OIDC_EXTRA_FLAGS` supplies trusted harness build flags.
Qualifying a control requires successful compilation followed by the intended
runtime assertion failure and a restored pass. A compiler failure is not red
evidence. These primitive checks do not qualify daemon credential selection,
actual-daemon error/admission behavior, binary transport, SDKs, or providers.

The separate [daemon acceptance suite](../tests/test_oidc_access.py) requires a
fresh normal or fatal ASan/UBSan build plus its test-only clock/verifier wrapper:

```sh
make BUILD_DIR="$build" all "$build/yamora-oidc-access-faults"
YAMLDB_BUILD_DIR="$build" \
YAMORA_OIDC_FAULT_BINARY="$build/yamora-oidc-access-faults" \
python3 -m unittest yamora.tests.test_oidc_access -v
```

Use an absolute, task-owned build directory. Missing executables fail. The
wrapper is never linked into the production daemon. Acceptance covers exact
YAML, strict startup rejection with a valid policy control, static/certificate
precedence, large-body expiry and reservation release, immutable key rotation,
binary exclusion and authorization before replica-set receipt replay. Eight
isolated guard-removal daemon controls separately cover signature, issuer,
audience, algorithm, token type, scope, expiry and static precedence; each must
fail its intended assertion after successful compilation and pass restored.
Provider interoperability, cloud IAM and SDK token acquisition remain unqualified.
