# Contributing

## Before Editing

1. Read [`AGENTS.md`](AGENTS.md) and the affected package's docs.
2. Run the affected package's deterministic tests as described below.
3. Identify owned dependencies and reverse dependants in `modules.json`.
4. Preserve unrelated work and generated/corpus provenance.

## Changes

Keep commits focused and conventional. Update every affected changelog with
the behavior and migration impact. Public API changes require compatibility
evidence and documentation. Specification behavior requires a decision record,
fixture coverage, and interoperability evidence.

New direct dependencies and dependency updates must follow the
[dependency governance policy](AGENTS.md#dependencies-and-supply-chain). Package-local
update bots are forbidden; the root policy owns every module and action update.

Specification-backed changes must follow the
[specification governance contract](AGENTS.md#design), update
the affected stable decision entries, and complete the Specification Decisions
section of the pull request template. An unresolved interpretation or stale
source pin is release-blocking; peer behavior cannot silently select policy.
The [specification decision register](docs/specification-decisions.md) and its
machine conformance bindings must preserve superseded entries and add a new
history digest whenever a recorded decision changes.

Selected full/release mutation gates must finish with zero surviving viable
mutants; mutation is not an ordinary local or pull-request prerequisite.

Do not add package-local workflows, permanent replacements, machine-specific
paths, bypass flags, broad mutation exclusions, or aggregate quality metrics
that hide a failing package.

## Verification

Use Go 1.27.3 for verification; the module/API minimum remains Go 1.27.0.
An isolated checkout needs no sibling repositories or coordination goal files.
Begin with deterministic tests and one active target when its parser boundary
changes, using a disposable cache for each bounded session:

```bash
(
  GOCACHE="$(mktemp -d)"
  export GOCACHE
  trap 'rm -rf "${GOCACHE}"' EXIT
  GOWORK=off go test ./...
  GOWORK=off go test . -run '^$' -fuzz '^FuzzParseTokenIsBounded$' -fuzztime=2s -timeout=2m
)
```

Deterministic tests execute fuzz seeds/corpus, not active fuzzing. The direct
command above omits `integration` tests and does not qualify durable backends.
Install the verified public v2.4.0 binary archive for your platform from
[go-library-tools releases](https://github.com/faustbrian/go-library-tools/releases/tag/v2.4.0),
checking `checksums.txt` against `.golib.yaml` and the archive against that
checksum set. Add the extracted `golib` binary to `PATH`; do not build Tools
from source. CI verifies the same published release while checking out the
pinned reusable workflow source.

```bash
make inventory
make check
make ci
make specification-check
golib mutation --module . --package .
```

Run adjacent Make commands inside one disposable-cache session as shown above;
the owned protocol target inherits that session's cache rather than creating a
new build cache between the local check and conformance.

`make check` and `make ci` run the bounded local contract with the declared
PostgreSQL/Valkey fixtures and `integration` tag; they are not Docker- or
database-free. Both retain the owned protocol guard: seven native vector,
canonicalization, URL-refusal, atomic replay, revocation and Python-token tests,
plus Python standard-library HMAC interoperability and the seven-source/
eleven-decision inventory guards. CI requires both the shared workflow and
the five-minute protocol job to succeed. The targeted root race runs once
with a two-minute timeout and proves exactly one of 32 contenders consumes
a one-use grant. CI also validates repository/cohesion structure; specification
checking is offline unless explicitly requested online. Base-free checks run
seeds/corpus; changed-source CI selects causal active fuzz smoke. Optional
mutation is limited to one package, one worker and a twenty-minute deadline.

Select full qualification and release rehearsal explicitly:

```bash
make check-full
make conformance
make interoperability
make specification-check-online
golib api check
golib release dry-run --module .
```

The native conformance/interoperability Make targets require Go and Python 3;
wrap direct `make conformance` runs in the same disposable-cache session shown
above. Full checks retain all three declared fuzz targets at 10000x/2m each,
clean-consumer, conformance/interoperability, benchmarks and original module
gates. Online specification verification fetches pinned authority/errata
sources. Release rehearsal can run locally. Report unavailable or failing
commands; bounded checks alone do not establish release qualification.

## Adding A Module

Follow [repository structure policy](AGENTS.md#repository-structure). New modules
require an explicit purpose, ownership boundary, dependency review, package
catalog entry, full quality gates, documentation, changelog, license, security
policy, compatibility plan, and release dry-run.

## Source Documentation

Install the checksum-pinned public verifier declared in `.golib.yaml`.
`make source-docs-check` validates objective Go comment, marker, link and
generated-producer structure; `make check`, `make check-full` and `make ci`
require it before their existing checks. Shared CI runs the same strict
contract and includes its result in Required. This is structural enforcement,
not a substitute for source-truth review or behavioral verification.
