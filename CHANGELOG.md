# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/) and
the module follows semantic versioning.

## [Unreleased]

### Changed

- Track the pinned documentation-tool lockfile so clean CI checkouts install
  the exact validated cspell dependency.

- Reconcile standalone dependency checksums against deterministic current
  module archives so CI, local verification, and release consumers resolve
  identical content.

- Harden standalone documentation validation with deterministic spelling and
  link checks, package-specific documentation gates, and repository-local
  contributor guidance.

## [1.0.0] - 2026-08-25

### Documentation

- Link the package README to the repository-wide Golib documentation portal.

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
