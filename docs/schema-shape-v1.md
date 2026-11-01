# Native shape kernel v1

This kernel compiles a closed shape profile and checks borrowed parsed values.
Standalone profile-7 policy storage and admission use it. It does not claim
JSON Schema, OpenAPI, or CRD compliance; replicated enforcement remains open.
The public API and exact precharge schedule are frozen in `../src/schema/shape.h`.

## Classification and traversal

Every schema node is a mapping with a mandatory string `type`. Supported types
are `object`, `array`, `string`, `boolean`, `null`, `integer`, and `number`.
Objects alone allow `properties` (literal-name mapping, default `{}`), `required`
(unique string list, default `[]`), and `additionalProperties` (boolean, default
`true`). Required names need not appear in properties. Arrays require one
homogeneous `items` schema. Other types allow only `type`.

At each node, first check depth and then node-count caps, then mapping form; scan unknown
keywords in source order before resolving the mandatory type. Then validate
supported keyword forms and compile children in keyword/property input order.
Thus an unknown keyword takes precedence over a missing type. A misplaced known
keyword is unsupported when encountered after resolving the type. Type lists
and items lists explicitly denote unsupported unions/tuples. Unknown type
strings are unsupported. Missing type/items, nonmapping nodes, wrong supported
keyword value types, and duplicate required names are invalid. Parser rejections
(including duplicate YAML keys, unsafe YAML features, and malformed UTF-8) are
invalid; allocation failures are errors. Only bounded enum/location errors cross
the API. Input strings and parser messages never do.

Schema ordinals are 1-based preorder in input order; the root counts as depth 1.
Compilation locations have document depth 0. Preparse and argument locations are
0/0. At evaluation, required/extra/budget errors name the current schema object
and document container depth; child type errors name the child. Success clears
all error fields. Error output is optional; compile output and check budget are
mandatory. Every compile failure clears `*out` without freeing its prior value.

## Bounds, ownership, and checks

Inclusive bounds: 32768 source bytes, 256 schema nodes, schema depth 16,
64 properties and 64 required names per object, 16384 total owned name bytes,
and 262144 requested compiled allocation bytes. Every copied name counts its
trailing NUL; property and required copies count separately. Charged allocations
include the program and alignment/ownership headers. Fixed-capacity object tables
reserve the profile's 64 property and required slots; their full cost is charged.
Temporary parser storage and libc bookkeeping are outside the compiled bound.
These limits do not change the existing document parser's limits. YAML grammar
limits also remain in force: long property names can use explicit mapping keys.
The name cap is checked before its allocation; the allocation cap is checked
before malloc. Earlier failures are not replaced by later failure locations.

Compiled programs own their storage and retain neither source bytes nor the
parser tree. Checks borrow a live immutable YDValue tree; they allocate and mutate
nothing and perform no I/O or clock calls. Callers join checks before freeing a
program or document. A program and document can be shared, with separate budget
and error objects for concurrent calls. `free(NULL)` is safe.

The exact input-order, depth-first precharge schedule is in the header. In
particular, it accounts for key scans including terminators and repeated equal-
length key comparisons, including required membership/presence checks. Unknown
extra values are not traversed when they are allowed. A failed precharge consumes
the residual balance and performs no associated work. Balances persist across
checks; the admission default is 1048576 and the kernel never resets it.
An exact final balance of zero may succeed. Integer means YD_INT only; number
means YD_INT or finite YD_FLOAT. No coercion, defaults, pruning, extensions, or
missing-as-null behavior exists. The first failure in the frozen traversal wins.

## Focused verification

The discoverable `yamora.tests.test_schema_shape` module builds only the kernel,
existing value parser, libyaml, math, and pthread support. It does not require a
daemon or SSL. Tests cover public behavior, inclusive bounds, shared budgets,
lifetimes, allocation failures, independent concurrent checks, exact source
bytes, and bounded diagnostics. Test-only mutants must fail named semantic
assertions; compiler errors, sanitizer findings, signals, and timeouts are not
behavioral red evidence.

Run `python3 -m unittest -v yamora.tests.test_schema_shape` through the configured
managed task runner. The compiler defaults to Clang and accepts the existing
`CC` override. All temporary binaries follow the task runner's `TMPDIR`.

## Independent bounded JSON assertion kernel

`yd_json_schema_compile`, `yd_json_schema_check` and `yd_json_schema_free` expose
the separate opaque `YDJSONSchema` program. Its profile identifier is
`yamora-json-logic-2020-12-v1`. It implements a closed assertion subset using
[JSON Schema 2020-12 Core](https://json-schema.org/draft/2020-12/json-schema-core)
and [Validation](https://json-schema.org/draft/2020-12/json-schema-validation).
Callers select it by its separate API. The existing `YDSchema` API, records,
budgets and `yamora-shape-v1` durable identity keep their original behavior.

Supported schemas are booleans and maps containing only these keywords:

| Form | Assertion |
| --- | --- |
| `true` or `{}` | Accept any parser-produced value. |
| `false` | Reject every value. |
| `type` | One of the seven type names, or a nonempty list of unique names. |
| `allOf` | Every child schema must accept. |
| `anyOf` | At least one child schema must accept. |
| `oneOf` | Exactly one child schema must accept. |
| `not` | Its single child schema must reject. |

Composition lists must be nonempty. Adjacent keywords are conjunctive, evaluated
in source order. Schemas need no `type`; object/array type assertions do not
inspect their contents. Integer accepts numeric values with zero mathematical
fractional part, including `1.0`, `1e3` and `1200e-2`. Its decision uses the
retained decimal spelling, so rounding a tiny fractional suffix to an integral
`long double` cannot admit it. Boolean values remain distinct from numbers.
In YAML schemas, quote the type name `"null"` to distinguish it from null itself.

This profile rejects every unimplemented keyword as `UNSUPPORTED`, including
`$schema`, references, annotations, `properties`, `items`, numeric/string bounds,
`enum`, `const` and Kubernetes extensions. This is deliberately a closed subset;
it does not implement general JSON Schema unknown-keyword annotation behavior.
No OpenAPI document selection, CRD structural validation, defaulting, coercion,
pruning or external resource loading occurs. The safe native YAML value parser
still bounds Unicode, numeric range and document size. Arbitrary-precision JSON
numbers and JSON strings outside that parser's safe profile are not supported.

Compilation checks source size before parsing and uses inclusive limits of
32,768 source bytes, 256 schema nodes and depth 16. Unknown keywords are checked
before supported forms at each map. The complete program uses one fixed-size
allocation, statically bounded below 262,144 bytes; temporary parser allocations
are outside this bound. There are no copied property names. Failure clears the
output pointer and never frees the caller's previous program. Programs retain
neither source nor parser tree; evaluation allocates and mutates nothing.

One caller-owned `YDSchemaBudget` spans all branches and repeated checks. Charge
one before each schema node and each keyword. An integer test on a floating
scalar additionally charges each spelling byte, including NUL, before reading
it. A union that also allows `number` needs no integer spelling scan. `allOf`
stops at the first rejecting child, `anyOf` at the first accepting child and
`oneOf` at its second accepting child. These shortcuts collect no annotations.
Visited `LIMIT` and `ERROR` results propagate through every composition,
including `not`; neither becomes an ordinary rejection or receives a fresh
budget. Exact zero balance may succeed. Errors expose only bounded enum codes,
preorder schema ordinals and document depth 1. Successful checks clear errors.
Concurrent checks share immutable programs/documents with separate budgets and
errors; join them before freeing either input.

The logic API remains a separate closed kernel. Durable document policies use
the explicit document profiles below; the logic profile name itself is not
installable in a collection catalog. The focused native harness
checks the new semantics alongside every existing v1 scenario with fatal
ASan/UBSan, exact budgets, ownership, concurrency and allocation-failure probes.

## Durable document and extraction profiles

Bare policy source retains the exact `yamora-shape-v1` semantics and durable
hashes. New policies select a separate profile using an envelope, for example:

```yaml
profile: yamora-json-schema-2020-12-v1
schema:
  type: object
  properties:
    value: {type: [integer, "null"]}
  required: [value]
  additionalProperties: false
```

`yd_json_document_compile` adds `properties`, `required`,
`additionalProperties` (a boolean or schema), and homogeneous `items` to the
logic assertions above. A matching `$schema` declaration must equal
`https://json-schema.org/draft/2020-12/schema`. Object assertions apply only to
objects and `items` only to arrays; they do not require an adjacent `type`.
Properties and additional properties use the same node's property declarations
regardless of keyword order. Names are literal, including dots and slashes.
Required names are unique strings; an empty required list is valid.

Programs retain no source/tree and evaluate without allocation. The common
source/node/depth/allocation limits apply. Each object node allows 64 properties
and 64 required names; programs allow 255 property declarations, 256 required
names and 16 KiB copied names including NULs. Every member visit, required-name
visit and name-comparison byte (including NUL) is charged before inspection.
Matched property and item checks share the caller's budget with all composition
branches; errors identify the actual nested document depth.

The OpenAPI envelope selects one literal component name:

```yaml
profile: yamora-openapi-3.1-schema-v1
name: Record
document:
  openapi: 3.1.1
  components:
    schemas:
      Record: {type: object, properties: {value: {type: integer}}}
```

Only OpenAPI 3.1.0, 3.1.1 and 3.1.2 documents are accepted. An explicit
`jsonSchemaDialect` must be the OpenAPI 3.1 base dialect. Selection reads
`components.schemas[name]`; it does not interpret paths, request/response
direction, discriminators or references. See the owning
[OpenAPI schema contract](https://spec.openapis.org/oas/v3.1.1.html#schema-object).

The CRD envelope uses `profile: yamora-crd-v1-schema-v1`, a literal `version`,
and `document` with `apiVersion: apiextensions.k8s.io/v1` and
`kind: CustomResourceDefinition`. It selects exactly one
`spec.versions[].schema.openAPIV3Schema` by unique version name. There are at
most 64 version records and the selected root must declare `type: object`.
The selected schema uses the same closed assertions. This is schema extraction
and enforcement, not a Kubernetes API server: it implements no admission
webhooks, CEL, conversion, defaulting or pruning. See the
[Kubernetes validation contract](https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definitions/#validation).

All envelope bytes, including the selected document and selector, count toward
the 32 KiB policy-source limit and remain the exact durable source. Unknown
envelope fields, unknown profiles, references, annotations other than the exact
`$schema`, regex/string/numeric bounds, `enum`, `const`, unevaluated/pattern
properties, tuples, nullable and Kubernetes extensions fail explicitly; no
keyword is silently treated as enforced. The native safe YAML numeric and
Unicode domain remains authoritative. These bounded profiles do not claim
complete JSON Schema/OpenAPI/Kubernetes compliance.
