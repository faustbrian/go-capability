# Compatibility Policy

Each releasable directory is an independent Go module and follows semantic
versioning. Nested-module tags use `<module-directory>/v<version>`; this root
module uses root tags such as `v2.x.y`.

Version 2 uses `github.com/faustbrian/go-capability/v2`. All seven public
package paths use the `/v2` module suffix, including the retained facades. The token wire remains v1.
The [v2 API snapshot](api/README.md) establishes a new source baseline, not
compatibility with the unversioned v1 module. Explicit issuer policy,
issuer-scoped replay/migration, finite defaults and sanitized policy errors
require deliberate consumer adoption. See [migration](docs/adoption.md#module-and-import-paths-v2-source).

Before `v1`, minor releases MAY contain reviewed breaking changes, but every
break MUST be documented with migration guidance. Patch releases MUST remain
backward compatible. At and after `v1`, incompatible exported API or documented
behavior changes require a new major version.

Compatibility includes exported Go APIs, error classification, serialization,
protocol behavior, persistence schemas, environment variables, command output,
resource ownership, ordering, retry/idempotency semantics, and documented
defaults. A compile-compatible change can still be behaviorally breaking.

Specification-backed modules MUST NOT diverge from their declared standards.
Ambiguities require documented decisions and stable tests. Deprecated APIs
follow [`DEPRECATION.md`](DEPRECATION.md).

The deprecated `caphttp` and `memory` paths remain supported until the longer
of 180 days after their `adapters/http` and `adapters/memory` successors first
resolve publicly and two subsequently published stable minor releases that
contain both paths. Removal additionally requires owned-consumer migration,
clean external-consumer evidence, continued correctness and security
maintenance, and a separately authorized next-major release.

The [specification decision register](docs/specification-decisions.md) is part
of this compatibility contract. Any changed wire, parser, validation,
canonicalization, resolution, or transport decision requires compatibility and
changelog review even when prior behavior was undocumented.
