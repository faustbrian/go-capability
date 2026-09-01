# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/) and
the module follows semantic versioning.

## [Unreleased]

### Changed

- Adopt the pinned `go-library-tools` v1.2.0 CLI and reusable workflow so CI
  enforces specification decisions, conformance bindings, source monitoring,
  and change control while retaining package-owned policy and verification
  evidence.

### Documentation

- Replace the archived monorepo link with package-owned documentation.
- Add machine-validated source monitoring, conformance bindings, change
  control, and append-only history for the [capability specification decision
  register](docs/specification-decisions.md). The recorded choices preserve
  existing capability-v1 behavior.

### Specification Decisions

- CAPABILITY-DEC-001 sha256:1107fd84dbd9852b589f4b12a1351aed9b5e74191b854e777223800fb96c9cef
- CAPABILITY-DEC-002 sha256:d456c41ac0360f68c49735a010fc92792d7dc736f5c1eb769ec3a6e5c766706d
- CAPABILITY-DEC-003 sha256:516adafa8914f8d8a0df34e3e463b0c205cdcfe40b5f76dc5cc6fe04ed1602a4
- CAPABILITY-DEC-004 sha256:fb77e88e5663fdbb9dc2d791ed363c91284bdd375aae3bc0f129c91d85d4a6c7
- CAPABILITY-DEC-005 sha256:e273f0a3be717a603ab549112ca6a17b4dddf63aa9822ea439512044d7eaa334
- CAPABILITY-DEC-006 sha256:eb9a9c432b3f6077538ec0df68d9f774587eea8ec5c03855e3d815d436e9fef7
- CAPABILITY-DEC-007 sha256:490891032e747f235527996acc36073b4a75115e5c37ae22ba7a925d30959e81
- CAPABILITY-DEC-008 sha256:b9f2c3c55dd271192f3b33581c9bd51542c0b04e30671b397f4503690c342468
- CAPABILITY-DEC-009 sha256:827d866d641c94c5f8238ada6aa89ecacaf883596c040b29dda676f85da54106
- CAPABILITY-DEC-010 sha256:69e3e668def16e00dd7cf0ed4ef345a71b5f8b38805d0e15c891a1da6767f926
- CAPABILITY-DEC-011 sha256:ccbb5b4d4206f52b03b96fb73ba1ee792ec83f9afbd48bce25edc20905e05d14

## [1.0.0] - 2026-08-25

### Changed

- Exclude intentional nested modules from root local-proxy archives so local,
  bootstrap, CI, and public module checksums describe the same source
  boundary.

- Track the pinned documentation-tool lockfile so clean CI checkouts install
  the exact validated cspell dependency.

- Reconcile standalone dependency checksums against deterministic current
  module archives so CI, local verification, and release consumers resolve
  identical content.

- Harden standalone documentation validation with deterministic spelling and
  link checks, package-specific documentation gates, and repository-local
  contributor guidance.

### Documentation

- Link the package README to package-owned documentation.

### Added

- Auditable capability-v1 specification decisions, expanded RFC provenance,
  and one conformance gate linking every protocol choice to executable
  evidence.

- Canonical versioned capability payloads with explicit issuer, audience,
  subject or bearer mode, resource, operation, time, ID, tenant, correlation,
  bounded use, and caveat semantics.
- HMAC-SHA-256 and Ed25519 signing with protected algorithm/key identifiers,
  immutable rotation key sets, bounded remote resolution, lifecycle policy,
  and downgrade rejection.
- Deterministic absolute and explicitly relative signed URLs covering method,
  authority, path, allowlisted query parameters, expiration, and optional body
  digests while rejecting ambiguous or smuggled representations.
- Separate parsing, verification, authorization, replay consumption, and
  revocation contracts with process-local, PostgreSQL, and Valkey atomic
  consumption adapters.
- Live PostgreSQL and Valkey integration coverage for replay durability across
  client recreation, with required services declared in the module manifest.
- Secret-safe failure categories that discard arbitrary provider and adapter
  causes while preserving cancellation and deadline classification.
- Explicit `net/http` middleware and HTTP-client integration that keeps
  application authorization and consumption visible.
- Threat model, protocol, proxy, replay, revocation, migration, adoption,
  failure-mode, and FAQ documentation.

### Changed

- Publish the module from its standalone `github.com/faustbrian/go-capability` identity while preserving its documented API and behavior.
- Invalid-profile verification now isolates every required URL-profile field,
  preventing logical-condition mutations from surviving through timeouts.
- Verification now preserves trusted unknown-key and algorithm-mismatch policy
  failures through bounded resolver layers while continuing to redact private
  resolver diagnostics.
- Durable replay integration now proves acknowledged consumption survives an
  abrupt caller-process exit in both PostgreSQL and Valkey deployments.

[Unreleased]: https://github.com/faustbrian/go-capability/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/faustbrian/go-capability/releases/tag/v1.0.0
