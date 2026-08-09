# Deployment profiles

## Download

- method `GET`;
- HTTPS-only absolute origin from static configuration;
- one exact file resource and `download` operation;
- bearer mode, short expiry, reusable only when repeated range requests are
  intended;
- allowlisted presentation query fields only.

## Upload or callback

- exact `PUT` or `POST` method;
- HTTPS-only absolute origin;
- required SHA-256 body digest when the complete body is known at issuance;
- one-time or tightly bounded use with durable consumption;
- subject binding when the caller is independently authenticated.

## Invitation or one-time action

- explicitly relative URL only when the application supplies the origin by
  route configuration;
- one exact action resource and method;
- `MaxUses: 1` with consumption ordered transactionally before the protected
  transition, or an idempotent transition plus reconciliation;
- expiry measured in minutes, not session lifetime.

## Service handoff

- Ed25519 when recipients should receive only public verification keys;
- explicit service audience and tenant;
- resource and operation vocabulary owned by the receiving service;
- correlation metadata is diagnostic and never grants authority;
- rotation overlap ends only after old capabilities expire plus accepted skew.

## Reverse proxies

Configure `caphttp.Verifier.Origin` from trusted deployment configuration. The
adapter ignores request host and forwarding headers. If dynamic external-origin
selection is unavoidable, validate trusted proxy metadata before constructing
the `URLRequest`; never pass arbitrary `Forwarded` or `X-Forwarded-*` values to
the canonicalizer.

Do not forward a signed URL across a redirect to a different scheme, authority,
path, or covered query. Issue a new capability for the exact redirect target.
Client retries of the same URL are safe only when the capability is reusable or
the protected operation has explicit bounded-use reconciliation; never retry an
unknown consumption outcome automatically.
