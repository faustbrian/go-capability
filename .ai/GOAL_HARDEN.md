# Goal Harden: `capability`

## Mission

Perform an adversarial protocol, cryptographic-use, canonicalization, replay,
revocation, key-lifecycle, and deployment audit of `capability`.

## Required Audit

1. Inventory payload versions, profiles, covered components, algorithms, key
   resolvers, stores, adapters, defaults, errors, and diagnostic paths.
2. Threat-model token theft, confused deputies, capability widening, parser
   differentials, URL ambiguity, replay races, key compromise, downgrade,
   timing leakage, proxy rewriting, clock manipulation, and denial of service.
3. Prove every parsed representation maps to one canonical signed meaning;
   reject duplicate or ambiguous alternatives.
4. Verify method, scheme, authority, port, path, query, content digest, audience,
   resource, operation, tenant, time, and caveat enforcement independently.
5. Exercise key rotation, overlap, removal, wrong key types, unknown key IDs,
   resolver outage, stale cache, cancellation, and compromise response.
6. Prove atomic one-time consumption under concurrency, retries, process death,
   PostgreSQL/Valkey failover, unknown outcomes, and cleanup.
7. Verify revocation propagation and explicitly bound stale acceptance windows.
8. Fuzz all decoders and canonicalizers; run official vectors, differential
   tests, race tests, leak tests, and constant-time-sensitive review.
9. Test middleware ordering with authentication, authorization, tenancy,
   correlation, audit, body limits, proxies, redirects, and retries.
10. Confirm secrets and capability contents are appropriately redacted from
    every observable output.

## Required Evidence

- independent interoperability and canonical golden vectors;
- exact 100% meaningful statement coverage and 100% viable mutation kills;
- race, fuzz, stress, soak, leak, fault-injection, and hostile-input results;
- replay-store durability and failover exercises;
- algorithm and key-lifecycle security review;
- benchmarks for issue, verify, revoke, and consume with bounded allocations;
- complete deployment profiles, migration guidance, and clean-consumer proof.

No security claim may be based on coverage percentage, algorithm reputation, or
happy-path vectors alone.
