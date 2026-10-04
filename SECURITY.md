# Security policy

## Supported versions

Pin an exact capability module version and review every upgrade. Only versions
explicitly listed in [repository release notes](https://github.com/faustbrian/go-capability/releases) are
supported.

## Reporting

Report suspected vulnerabilities through the
[private security-advisory workflow](https://github.com/faustbrian/go-capability/security/advisories/new).
Do not include live capabilities, signing keys, URLs containing
capabilities, or unredacted service output. Include the affected version,
profile, deployment topology, and a reproduction using generated test keys.

Severity classification, acknowledgement and remediation targets, embargo
handling, advisories, and coordinated releases follow the shared
[ecosystem vulnerability-management policy](https://github.com/faustbrian/go-library-tools/blob/main/docs/ecosystem/security/vulnerability-management.md).

## Boundary

This module authenticates explicitly encoded capability authority. Operators
still own TLS, key generation and secret storage, external-origin trust,
application authorization, durable replay ordering, revocation consistency,
audit redaction, and incident response. It provides neither confidentiality nor
an exactly-once side-effect guarantee.
