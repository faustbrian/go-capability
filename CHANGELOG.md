# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/) and
the module follows semantic versioning.

## [Unreleased]

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

- Invalid-profile verification now isolates every required URL-profile field,
  preventing logical-condition mutations from surviving through timeouts.
- Verification now preserves trusted unknown-key and algorithm-mismatch policy
  failures through bounded resolver layers while continuing to redact private
  resolver diagnostics.
- Durable replay integration now proves acknowledged consumption survives an
  abrupt caller-process exit in both PostgreSQL and Valkey deployments.
