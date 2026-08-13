# Capability specification decisions

This register records every material interpretation and package-owned policy in
the capability v1 token and signed-URL profiles. Normative sources and exact
digests are pinned in the [source manifest](../specification/manifest.tsv).
Passing cryptographic vectors proves algorithm use, not the surrounding
authority, canonicalization, replay, or deployment policy.

Statuses are `resolved`, `unresolved`, or `superseded`. A changed decision
requires protocol, security, resource, compatibility, executable-evidence, and
changelog review.

## CAPABILITY-DEC-001: Local capability protocol identity

| Field | Decision |
| --- | --- |
| Status and owner | `resolved`; `capability` maintainers |
| Source | RFC 4648 [base64url](https://www.rfc-editor.org/rfc/rfc4648.html#section-5), RFC 8259 [JSON grammar](https://www.rfc-editor.org/rfc/rfc8259.html), and RFC 9110 [HTTP semantics](https://www.rfc-editor.org/rfc/rfc9110.html) |
| Classification | Package-defined protocol constrained by referenced standards |
| Issue | No referenced standard defines a generic capability token, its authority fields, canonical bytes, signed-URL profile, or lifecycle. Calling the format JWT, Macaroon, PASETO, OAuth, or HTTP Message Signatures would import incompatible semantics. |
| Credible interpretations | Adopt an existing general token; expose unversioned helpers; serialize arbitrary claims; or define one narrow, explicitly local and versioned capability protocol. |
| Known peer behavior | JWT, PASETO, Macaroons, OAuth access tokens, and provider signed URLs encode different trust, delegation, caveat, and canonicalization models. Their popularity does not make them wire-compatible peers. |
| Selected behavior | `cap1` is a local v1 protocol for explicitly encoded resource operations. It claims compatibility only with its published canonical profile and isolated RFC algorithm and encoding primitives. Unknown versions and token types fail closed. |
| Security and resource consequences | The narrow profile prevents accidental authority widening and keeps every field and token length bounded. It does not provide confidentiality or legal non-repudiation. |
| Compatibility and wire consequences | Consumers must treat the complete `cap1` grammar as the wire contract. Another token family requires a separate adapter and cannot be accepted through permissive fallback. |
| Executable evidence | `TestIssueAndParseRejectEveryFramingBoundary`, `TestCanonicalPayloadHasOneStableRepresentation`, and `FuzzParseTokenIsBounded` |
| Public surface | `Issue`, `Parse`, `Verify`, `Header`, `Payload`, `Grant`, and all signed-URL APIs |
| Upstream record | No upstream specification owns this local profile; the referenced RFCs govern only their named primitives. |
| Reconsider when | A separately versioned profile is designed against a named external protocol with complete independent interoperability evidence. |

## CAPABILITY-DEC-002: Algorithm and key-type binding

| Field | Decision |
| --- | --- |
| Status and owner | `resolved`; `capability` maintainers |
| Source | RFC 2104 [HMAC](https://www.rfc-editor.org/rfc/rfc2104.html), RFC 4231 [HMAC-SHA-256 vectors](https://www.rfc-editor.org/rfc/rfc4231.html), and RFC 8032 [Ed25519](https://www.rfc-editor.org/rfc/rfc8032.html) |
| Classification | Normative cryptographic primitives with defensive algorithm policy |
| Issue | Standards define algorithms but do not authorize a token header to choose trusted verification policy, bind one key ID to several key types, or downgrade after a mismatch. |
| Credible interpretations | Trust the header algorithm; try every key or algorithm; infer algorithms from key length; or require an exact trusted algorithm and key-type binding. |
| Known peer behavior | General token frameworks often expose broad algorithm registries or algorithm negotiation. That flexibility is not imported into this deliberately small profile. |
| Selected behavior | The package supports only HMAC-SHA-256 and Ed25519. Constructors bind exact standard-library key types, each resolved key declares one trusted algorithm, and a header mismatch is terminal. No untrusted field can widen the allowlist. |
| Security and resource consequences | Algorithm confusion and downgrade are rejected before expensive or alternate verification. HMAC keys are copied, bounded, and compared through standard-library constant-time MAC verification; private key material never enters tokens or diagnostics. |
| Compatibility and wire consequences | The algorithm names `hmac-sha256` and `ed25519` are local profile values. Adding another algorithm requires an additive protocol decision and new independent vectors. |
| Executable evidence | `TestHMACSHA256RFC4231Vector`, `TestEd25519RFC8032Vector`, `TestVerifyRejectsTamperingDowngradeAndInactiveKeys`, and `TestConstructorsRejectWrongKeyTypesAndCopyKeys` |
| Public surface | `Algorithm`, `Signer`, `Verifier`, cryptographic constructors, `ResolvedKey`, and `KeySet` |
| Upstream record | The algorithm bytes and vectors are checksum-pinned in the source manifest; no package-specific erratum changes them. |
| Reconsider when | A concrete cryptographic migration has reviewed standard-library support, downgrade analysis, vectors, and a versioning plan. |

## CAPABILITY-DEC-003: Canonical JSON and token framing

| Field | Decision |
| --- | --- |
| Status and owner | `resolved`; `capability` maintainers |
| Source | RFC 8259 [objects and numbers](https://www.rfc-editor.org/rfc/rfc8259.html#section-4), RFC 4648 [base64url](https://www.rfc-editor.org/rfc/rfc4648.html#section-5), and [padding rules](https://www.rfc-editor.org/rfc/rfc4648.html#section-3.2) |
| Classification | Normative syntax with package-defined canonical representation |
| Issue | JSON object ordering, duplicate member handling, optional-field omission, numeric spelling, Unicode normalization, and base64url padding are not one universal signed representation. Accepting several byte forms for one authority creates parser and signature differentials. |
| Credible interpretations | Sign arbitrary JSON bytes; normalize after decoding; accept padded and unpadded segments; preserve duplicate members; or define one encoder and require byte-for-byte canonical re-encoding. |
| Known peer behavior | JSON libraries differ on duplicate members and canonicalization. Generic base64url decoders commonly accept padding even when a profile emits none. |
| Selected behavior | Tokens contain exactly three unpadded base64url segments after the `cap1` prefix. Protected header and payload use fixed member order, canonical Unix-second integers, deterministic sorted audiences and caveat keys, exact UTF-8 bytes without normalization, and defined omission rules. Parsing re-encodes and rejects any non-canonical representation. |
| Security and resource consequences | One signed byte representation prevents duplicate-member, normalization, and alternate-encoding ambiguity. Token, segment, member, collection, and decoded-byte limits apply before authority is returned. |
| Compatibility and wire consequences | Semantically similar but differently ordered, padded, duplicated, normalized, or numerically spelled inputs are rejected. Producers must emit the package canonical form. |
| Executable evidence | `TestCanonicalPayloadHasOneStableRepresentation`, `TestProtectedHeaderRejectsUnknownTrailingAndNonCanonicalForms`, `TestParseRejectsMalformedAndAmbiguousTokens`, and `FuzzParseNeverAcceptsTwoPayloadRepresentations` |
| Public surface | `CanonicalPayload`, `ParsePayload`, `Issue`, `Parse`, `Limits`, `Header`, and `Payload` |
| Upstream record | RFC 8259 permits implementation limits and does not define this signature canonicalization; the policy is intentionally package-owned. |
| Reconsider when | A new token version adopts a published canonical JSON profile and migration preserves old verification until expiry. |

## CAPABILITY-DEC-004: Time interval and skew semantics

| Field | Decision |
| --- | --- |
| Status and owner | `resolved`; `capability` maintainers |
| Source | Go 1.26.6 [`time.Time`](https://pkg.go.dev/time@go1.26.6#Time) and RFC 9110 [date and time](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.7) as adjacent time representations; neither defines this capability interval |
| Classification | Package-defined temporal authorization policy |
| Issue | Issued-at, not-before, expiration, integer precision, equality boundaries, skew direction, and maximum lifetime can be interpreted differently even when all parties use Unix seconds. |
| Credible interpretations | Inclusive expiration; symmetric skew on every field; no lifetime bound; subsecond comparison; or one explicit half-open validity interval with bounded skew. |
| Known peer behavior | Token libraries vary on inclusive expiration and whether skew extends not-before, expiry, or both. Those defaults are not imported. |
| Selected behavior | Canonical values are UTC Unix seconds. Not-before is inclusive after subtracting bounded skew; expiration is exclusive after adding bounded skew. Issued-at cannot exceed the allowed future boundary, expiration must be later than not-before, and configured lifetime is finite. |
| Security and resource consequences | Finite lifetime and skew bound stolen-token exposure and prevent attacker-selected extreme durations. Caller-provided current time is explicit and no hidden clock or timer exists. |
| Compatibility and wire consequences | Subsecond values are intentionally truncated at issuance into canonical seconds. A token is invalid exactly at expiration plus accepted skew. |
| Executable evidence | `TestVerifyEd25519AndTimeBoundaries`, `TestClockSkewExtendsExclusiveExpiry`, `TestPayloadRejectsExpiryExactlyAtLaterNotBefore`, and `TestPayloadRejectsEitherNegativeTimeIndependently` |
| Public surface | `Payload.IssuedAt`, `Payload.NotBefore`, `Payload.ExpiresAt`, `VerifyOptions.Now`, `VerifyOptions.Skew`, and `Limits.MaxLifetime` |
| Upstream record | No referenced standard defines the complete interval; the exact local behavior is part of capability v1 compatibility. |
| Reconsider when | A new profile needs different precision or interval semantics and can be versioned without reinterpreting issued tokens. |

## CAPABILITY-DEC-005: Encoded authority and application authorization

| Field | Decision |
| --- | --- |
| Status and owner | `resolved`; `capability` maintainers |
| Source | RFC 9110 [authentication and authorization distinction](https://www.rfc-editor.org/rfc/rfc9110.html#section-11) and the package's local capability profile |
| Classification | Security boundary and least-authority application policy |
| Issue | Signature verification proves token integrity but does not prove that a concrete caller may perform an attempted operation. Subject and bearer modes, audiences, tenant, resource, operation, and caveats can otherwise be ignored or treated as general roles. |
| Credible interpretations | Return raw claims after verification; authorize any valid signature; infer missing dimensions; or require an explicit attempted-use comparison after verification. |
| Known peer behavior | General claim-token middleware often places decoded claims in context and leaves enforcement implicit. Capability systems vary in attenuation and delegated caveat models. |
| Selected behavior | A payload encodes one bounded resource and operation, explicit audiences, exactly one subject or bearer mode, optional tenant, and bounded application caveats. `Verify` authenticates that authority; `Grant.Authorize` separately compares every attempted dimension. No role, wildcard, hierarchy, or caveat interpreter is inferred. |
| Security and resource consequences | Callers cannot accidentally treat a valid signature as universal access through the typed API. Caveat size and count are bounded, but applications own caveat meaning and must fail closed on unknown required caveats. |
| Compatibility and wire consequences | Missing, extra, or mismatched authority dimensions reject use. Applications changing resource vocabulary or caveat semantics must version their profile rather than reinterpret existing grants. |
| Executable evidence | `TestGrantIsDefensiveAndRequiresEveryAuthorityDimension`, `TestPayloadValidationRejectsAuthorityAmbiguityAndUnboundedInput`, and `TestIssueVerifyAndAuthorizeHMACCapability` |
| Public surface | `Payload`, `Grant`, `Use`, `Verify`, `Grant.Authorize`, and caveat accessors |
| Upstream record | RFC 9110 supplies the adjacent distinction, while the concrete capability dimensions remain package-owned. |
| Reconsider when | A separately specified attenuation or delegated-caveat model defines complete evaluation and compatibility semantics. |

## CAPABILITY-DEC-006: Signed URL canonicalization

| Field | Decision |
| --- | --- |
| Status and owner | `resolved`; `capability` maintainers |
| Source | RFC 3986 [generic syntax](https://www.rfc-editor.org/rfc/rfc3986.html#section-3) and [reference resolution](https://www.rfc-editor.org/rfc/rfc3986.html#section-5), plus Go 1.26.6 [`net/url`](https://pkg.go.dev/net/url@go1.26.6) |
| Classification | URI interoperability with defensive package profile |
| Issue | Raw and parsed URLs can disagree around userinfo, default ports, case, escaped paths, dot segments, encoded slashes, duplicate query values, fragments, relative references, and parameter ordering. Signing one interpretation while routing another enables substitution and smuggling. |
| Credible interpretations | Sign raw text; sign decoded components; let the HTTP stack normalize; accept first or last duplicate; or define one strict profile and reject every non-canonical alternative. |
| Known peer behavior | Provider signed URLs use incompatible covered components and normalization. Framework query APIs commonly choose first, last, or all duplicate values. |
| Selected behavior | A named immutable profile allowlists schemes, canonical authorities, query names, and one signature parameter. Absolute URLs require allowlisted origin; relative URLs require explicit opt-in. Userinfo, fragments, traversal, encoded slashes, duplicate values, uncovered names, signature duplication, and non-canonical authority forms fail. Query output uses deterministic `url.Values.Encode`. |
| Security and resource consequences | Rejecting alternate routing representations prevents authority substitution and parameter smuggling. URL, path, query, parameter, and value sizes are finite before signing or verification. |
| Compatibility and wire consequences | Canonically equivalent accepted inputs produce one URL, while ambiguous but otherwise parseable URLs are incompatible. Canonicalization changes require a new profile name or token version. |
| Executable evidence | `TestSignAndVerifyAbsoluteURLCoversEveryProfileComponent`, `TestVerifyURLRejectsAmbiguitySmugglingAndDowngrade`, `TestURLProfileRejectsNonCanonicalAuthorities`, and `FuzzSignedURLRoundTripIsDeterministic` |
| Public surface | `URLProfile`, `URLRequest`, `SignURL`, `VerifyURL`, and URL-related `Limits` |
| Upstream record | RFC 3986 and `net/url` do not define this signing profile; their pinned component behavior constrains the local decision. |
| Reconsider when | A named external signed-URL profile is implemented in an isolated adapter with differential vectors. |

## CAPABILITY-DEC-007: Covered HTTP method, origin, and body digest

| Field | Decision |
| --- | --- |
| Status and owner | `resolved`; `capability` maintainers |
| Source | RFC 9110 [methods](https://www.rfc-editor.org/rfc/rfc9110.html#section-9), [URI origin](https://www.rfc-editor.org/rfc/rfc9110.html#section-4.3.1), and [content](https://www.rfc-editor.org/rfc/rfc9110.html#section-6.4) |
| Classification | Transport-specific security profile |
| Issue | A URL alone does not bind request method, externally trusted origin, proxy rewriting, or body bytes. Deriving origin from untrusted request fields or silently omitting a required digest can widen authority. |
| Credible interpretations | Trust Host and forwarding fields; bind only path; uppercase methods; hash bodies implicitly; or require an explicit profile, trusted origin, exact method, and digest pairing. |
| Known peer behavior | Reverse proxies and signed-URL providers disagree on forwarded-origin trust and covered request components. HTTP libraries may normalize method or URL fields independently. |
| Selected behavior | The profile signs the exact configured method and canonical URL. HTTP verification receives one trusted external origin from deployment configuration and ignores request Host and forwarding headers for authority. A profile either requires an exact SHA-256 body digest supplied through an explicit callback or forbids one; signing mutates a request only after all checks succeed. |
| Security and resource consequences | Proxy-controlled fields cannot redirect authority, downgrade scheme, or omit body integrity. Digest work remains caller-owned and bounded by the caller's body policy; the package does not buffer arbitrary bodies. |
| Compatibility and wire consequences | Method case, origin, path, query, profile, expiration, and optional digest are signed dimensions. Rewriting any covered component invalidates verification. |
| Executable evidence | `TestSignedURLInternalCaveatsAndCanonicalTransportFailures`, `TestVerifierRejectsInvalidProfilesOriginsSkewAndDigestPairing`, `TestSignRequestUsesExplicitClientMutationOnlyAfterSuccess`, and `TestVerifierBodyDigestCustomFailureAndBoundaryHelpers` |
| Public surface | `URLProfile`, `URLRequest`, `caphttp.VerifierOptions`, `caphttp.BodyDigest`, `caphttp.SignRequest`, and middleware verification |
| Upstream record | RFC 9110 defines message semantics but deliberately does not define this capability signature profile or proxy trust model. |
| Reconsider when | A deployment adopts a separately specified proxy-origin contract or streaming digest profile with equivalent ambiguity analysis. |

## CAPABILITY-DEC-008: Bounded-use replay consumption

| Field | Decision |
| --- | --- |
| Status and owner | `resolved`; `capability` maintainers |
| Source | RFC 9110 [idempotent methods](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.2.2) as an adjacent retry concept; it does not define capability consumption |
| Classification | Durable application state and unknown-outcome policy |
| Issue | One-time and bounded-use capabilities require a single atomic owner. Retrying after timeout or commit ambiguity can exceed the signed use count or duplicate the protected side effect. Process-local state cannot coordinate replicas. |
| Credible interpretations | Count in memory everywhere; consume after the side effect; retry every error; treat timeout as rejection; or expose atomic store ownership and unknown outcomes explicitly. |
| Known peer behavior | Token middleware commonly treats replay as cache membership. Databases and Valkey can acknowledge, time out, or fail at different points around a committed mutation. |
| Selected behavior | `MaxUses == 0` is reusable. Positive values require an explicit `ConsumptionStore` that atomically binds capability identity, expiry, and maximum uses. Terminal exhaustion and identity conflicts are distinct; every unclassified store failure is `ErrConsumptionUnknown`. The caller owns ordering, idempotency, and reconciliation with the protected side effect. |
| Security and resource consequences | Atomic consumption prevents concurrent overuse when the selected store is shared by all replicas. Counts, identities, expiry, and cleanup are bounded. Unknown outcomes fail closed without claiming that no mutation occurred. |
| Compatibility and wire consequences | Use count is signed and cannot be changed by storage policy. Process-local memory is not cluster-compatible; PostgreSQL or Valkey is required for shared durable ownership. |
| Executable evidence | `TestMemoryConsumptionIsAtomicAtTheUseLimit`, `TestConsumptionStoreRejectsConflictingIdentityAndExpiresState`, `TestStoreSerializesConcurrentOneTimeConsumption`, and `TestUnknownConsumptionOutcomeFailsClosed` |
| Public surface | `Payload.MaxUses`, `Consumption`, `ConsumptionResult`, `ConsumptionStore`, `Grant.Consume`, and memory, PostgreSQL, and Valkey adapters |
| Upstream record | No referenced standard defines this state machine; RFC 9110 idempotency does not resolve transaction commit ambiguity. |
| Reconsider when | A new adapter proves equivalent atomicity, durability, expiry, and unknown-outcome semantics under its deployment topology. |

## CAPABILITY-DEC-009: Revocation matching and consistency

| Field | Decision |
| --- | --- |
| Status and owner | `resolved`; `capability` maintainers |
| Source | RFC 9110 [authorization](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.1) provides no capability revocation protocol; this is package-owned verification policy |
| Classification | Application lifecycle and consistency policy |
| Issue | Revocation by capability, key, subject, resource, tenant, or issue time has different scope. Distributed stores may be stale or unavailable, and treating an outage as not revoked silently widens acceptance. |
| Credible interpretations | Revoke only IDs; infer hierarchy; fail open on outage; promise instant consistency; or expose exact match dimensions and let adapters document consistency. |
| Known peer behavior | Token systems use deny lists, key removal, short expiry, epochs, or provider introspection with different propagation guarantees. None determines this package's local contract. |
| Selected behavior | Verification submits an exact bounded `RevocationQuery` containing capability ID, key ID, subject, issuer, tenant, resource, and issued-at. A checker may match any documented dimension or a monotonic issued-before cutoff. Outage and cancellation fail closed. The memory implementation is explicitly process-local and no adapter may imply stronger consistency than it provides. |
| Security and resource consequences | Exact dimensions prevent accidental wildcard broadening, while fail-closed outages avoid accepting known-unverifiable grants. Queries and retained process-local entries are bounded by application policy. |
| Compatibility and wire consequences | Revocation does not alter token bytes. Acceptance can differ across replicas only within the configured store's documented propagation window; deployments must account for that window. |
| Executable evidence | `TestVerificationChecksEveryRevocationBoundary`, `TestRevocationOutageAndCancellationFailClosed`, and `TestRevocationsValidateAndKeepMonotonicCutoff` |
| Public surface | `RevocationQuery`, `RevocationChecker`, `VerifyOptions.Revocations`, and `memory.Revocations` |
| Upstream record | There is no upstream capability-v1 revocation standard; this policy remains local and explicit. |
| Reconsider when | A durable revocation adapter defines measurable propagation, outage, and recovery semantics that require additive public policy. |

## CAPABILITY-DEC-010: Key resolution and lifecycle snapshots

| Field | Decision |
| --- | --- |
| Status and owner | `resolved`; `capability` maintainers |
| Source | RFC 2104 [key requirements](https://www.rfc-editor.org/rfc/rfc2104.html#section-3), RFC 8032 [keys](https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.5), and Go 1.26.6 [`context`](https://pkg.go.dev/context@go1.26.6) for cancellation |
| Classification | Defensive key lifecycle and remote-provider policy |
| Issue | Key rotation, overlap, disablement, revocation, unknown IDs, remote latency, stale caches, and provider diagnostics can change acceptance or leak sensitive material. Starting hidden refresh goroutines would obscure ownership. |
| Credible interpretations | Cache forever; retry or fetch without a bound; try every key; expose provider errors; or use immutable local snapshots and one bounded caller-owned resolution operation. |
| Known peer behavior | JOSE key resolvers often refresh remote sets automatically and token libraries may collapse unknown key and algorithm mismatch. This package intentionally exposes neither behavior. |
| Selected behavior | `KeySet` is an immutable exact key-ID snapshot with algorithm, disabled, revoked, not-before, and not-after policy. `BoundedResolver` validates key ID and algorithm, derives a finite deadline, invokes one caller-provided resolver synchronously, and does not cache or start background work. Rotation publishes a new resolver snapshot explicitly. |
| Security and resource consequences | Lookup count, key-ID length, algorithms, and duration are bounded. Provider secrets and causes are discarded from public errors; cancellation remains classifiable. Applications own remote cache freshness and lifecycle. |
| Compatibility and wire consequences | A key is accepted only while its exact trusted lifecycle permits it. Removing or disabling a key immediately changes local acceptance; distributed propagation depends on caller-owned resolver deployment. |
| Executable evidence | `TestKeySetBindsKeyIDsToOneAlgorithmAndLifecycle`, `TestBoundedResolverRestrictsAlgorithmsKeyIDsAndDuration`, `TestBoundedResolverObservesRotationRemovalWithoutCaching`, and `TestOperationalErrorsPreserveClassificationWithoutExposingDiagnostics` |
| Public surface | `Key`, `ResolvedKey`, `Resolver`, `KeySet`, `BoundedResolverOptions`, and `BoundedResolver` |
| Upstream record | Cryptographic source standards do not define application resolver lifecycle; the bounded synchronous policy is local. |
| Reconsider when | A separate cache or remote-key adapter specifies freshness, synchronization, shutdown, outage, and compromise behavior without changing the core contract. |

## CAPABILITY-DEC-011: HTTP middleware failure and ownership boundary

| Field | Decision |
| --- | --- |
| Status and owner | `resolved`; `capability` maintainers |
| Source | RFC 9110 [status codes](https://www.rfc-editor.org/rfc/rfc9110.html#section-15) and Go 1.26.6 [`net/http.Handler`](https://pkg.go.dev/net/http@go1.26.6#Handler) |
| Classification | HTTP adapter policy and application ownership boundary |
| Issue | Middleware can conflate verification with authorization or consumption, expose token/provider details, read bodies implicitly, commit partial responses, or permit a failed request to reach the application. HTTP does not define one capability error representation. |
| Credible interpretations | Automatically authorize and consume; pass errors downstream; expose detailed causes; use framework state; or verify only and return one bounded secret-safe adapter response. |
| Known peer behavior | Framework token middleware often combines parsing, authentication, claims context, and policy. Error status and body details vary by library. |
| Selected behavior | `caphttp.Verifier` verifies before calling the next handler, stores an immutable grant in request context, and leaves authorization, consumption, and protected side effects explicit. Configuration and verification failures do not invoke the application. Default errors are bounded and redacted; custom error handlers and body-digest callbacks remain caller-owned. |
| Security and resource consequences | Invalid capability bytes, keys, signatures, caveats, and provider causes are not reflected. Middleware performs no hidden body buffering, service lookup, goroutine, retry, or state mutation. |
| Compatibility and wire consequences | The adapter's default failure status and body are package policy, not a standardized capability response. Applications needing another representation configure an explicit handler without changing verification semantics. |
| Executable evidence | `TestMiddlewareVerifiesButLeavesAuthorizationVisible`, `TestMiddlewareComposesWithExplicitApplicationOrdering`, `TestMiddlewareRejectsBeforeCallingApplicationAndRedactsFailure`, and `TestMiddlewareCustomErrorNilHandlerAndSigningValidation` |
| Public surface | `caphttp.VerifierOptions`, `caphttp.Verifier`, `caphttp.GrantFromContext`, `caphttp.ErrorHandler`, and `caphttp.BodyDigest` |
| Upstream record | RFC 9110 defines general response semantics but no capability-v1 transport mapping. |
| Reconsider when | A separately versioned public API profile standardizes capability failures, authorization, or consumption ordering. |

## Unresolved decisions

None for the currently supported capability v1 and signed-URL surfaces. A new
algorithm, token version, canonicalization rule, authority dimension, store,
resolver cache, proxy model, or transport mapping requires a new decision
before runtime implementation.
