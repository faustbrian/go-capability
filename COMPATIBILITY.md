# Compatibility Policy

Each releasable directory is an independent Go module and follows semantic
versioning. Tags use `<module-directory>/v<version>`.

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
