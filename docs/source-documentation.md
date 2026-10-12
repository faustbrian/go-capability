# Source documentation audit

## Scope, acceptance and inventory

This Tier A pass owns source prose at baseline
`77627acbb4b6483b133dab66947bad685761e4ab`: one v2 module, seven packages,
52 tracked Go files (20 maintained source and 32 test). Reproduce with
`git ls-files '*.go' 'go.mod' '**/go.mod'` and
`golib source-docs inventory --json`. The baseline has 112 objective exported
comment/member gaps. Three fuzz targets, seven benchmarks, five examples,
all test-file assertion contracts and complex store/clock/process fixtures
are included. PostgreSQL and Valkey each have an `integration` test variant;
there are no platform-specific, generated or vendored Go files. Two legacy
package deprecations retain their supported compatibility interval.

| Owner | Source contract and missing context |
| --- | --- |
| Core payload/token/crypto | Local cap1/v1, canonical decoded JSON, explicit issuer/key ownership, copied secrets versus borrowed collaborators, admission before decoding versus copy/allocation limits, primitive cancellation and fixed safe errors. |
| Grant/replay/revocation | Exact use dimensions, no authority from parsing, no automatic consumption or business transaction, known no-consume categories versus unknown outcomes, separate time/revocation/store decisions. |
| Resolver/URL | Snapshot policy versus borrowed verifiers, cooperative remote deadlines with no cache/worker, fixed key-ID bounds, immutable caller profiles, canonical presentation versus authorization/egress. |
| HTTP and retained facade | Static trusted origin, borrowed profile slices/clock/digest callbacks, pre-authentication body-digest work, mutation only on successful signing, nil next handling, shared context grant and application side-effect ownership. |
| Memory and retained facade | Per-store count/string budgets rather than exact heap limits, one synchronization owner, clock outside lock, finite admission and in-place owned keys, explicit cleanup/revocation lifecycle and loss on restart. |
| PostgreSQL/Valkey | Caller-owned client/schema/legacy-issuer proof, precision and server-clock expiry, bounded insert-race retry, unknown commit outcomes, parameter/declared-key boundaries and no business transaction coupling. |
| Test/fuzz/benchmark owners | Synthetic SQL/Valkey models versus real tagged durability fixtures, child exit/cleanup ownership, finite parser inputs and measured hot repeat versus first-admission workloads. |

Acceptance is useful rendered comments with unchanged executable tokens,
literals, directives, example outputs, API signatures, dependencies, SQL/Lua
and historical authority/review bytes. Local structure/links, changed-content
secrets, Go documentation/examples and one ordinary complete final-diff
inspection are selected. No unchanged database/Valkey, race, active fuzz,
conformance, performance or release campaign is selected.

## Specification and generation boundaries

Local interpretations remain [the decision register](specification-decisions.md)
and [pinned sources](../specification/manifest.tsv); cap1 is not JWT/JWS or
RFC 9421 interoperability. No current decision change is needed by this prose.
`api/baseline.txt` is native `apidiff` export data, not a full Go-doc snapshot;
its pinned regeneration recipe is [the API note](../api/README.md). Preserve it.
The independent Python script compares its deterministic token with
`testdata/v1-hmac.token`; it does not generate Go source. Embedded PostgreSQL
statements/migration files and the Valkey Lua script are executable artifacts,
not prose to rewrite.

## Source-backed investigation boundary

`Issue` admits a custom signer's key ID under caller-selected field limits,
then ignores the error from `canonicalHeader`, whose hard key-ID bound is
256 bytes. Larger limits with a custom ID above that bound can construct
an invalid protected header. Built-in signer constructors already impose the
256-byte bound. Keep custom IDs within that fixed contract; changing the
ignored-error behavior requires a separate runtime regression/fix, not this
prose pass. No guessed origin, compatibility rationale or security certification
is supplied. Very large custom limits also require caller allocation/arithmetic
review; default finite limits are not an exact process-memory guarantee.

The coordinator owns shared CI enforcement and remote-main qualification.
This audit does not refresh frozen security reviews, qualify external service
behavior or public release, or migrate consumers. Prose does not require a
module release or repin.

## Objective Enforcement

The checksum-pinned public Tools v2.4.0 verifier now supplies
`make source-docs-check` as a prerequisite of the existing local and CI Make
routes. Ordinary shared CI selects strict source-documentation checking and
requires its result. Native prerequisites, operation budgets, security and
release controls are retained. Hosted exact-head evidence is recorded by the
coordination ledger; configuration alone does not establish green delivery.
