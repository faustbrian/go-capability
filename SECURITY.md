# Security policy

## Supported versions

Pin an exact capability module version and review every upgrade. Only versions
explicitly listed in repository release notes are
supported.

## Reporting

Report suspected vulnerabilities with GitHub's private security-advisory
workflow. Do not include live capabilities, signing keys, URLs containing
capabilities, or unredacted service output. Include the affected version,
profile, deployment topology, and a reproduction using generated test keys.

## Boundary

This module authenticates explicitly encoded capability authority. Operators
still own TLS, key generation and secret storage, external-origin trust,
application authorization, durable replay ordering, revocation consistency,
audit redaction, and incident response. It provides neither confidentiality nor
an exactly-once side-effect guarantee.
