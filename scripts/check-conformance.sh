#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest="${root}/specification/manifest.tsv"
register="${root}/docs/specification-decisions.md"
expected_header=$'id\tversion\trole\tstatus\tsha256\tbytes\turl'

[[ -f "${manifest}" && -f "${register}" ]] || {
	printf 'missing capability specification evidence\n' >&2
	exit 1
}
[[ "$(head -n 1 "${manifest}")" == "${expected_header}" ]] || {
	printf 'invalid capability specification manifest header\n' >&2
	exit 1
}

required=(rfc2104 rfc4231 rfc3986 rfc4648 rfc8032 rfc8259 rfc9110)
seen='|'
count=0
while IFS=$'\t' read -r id version role status digest bytes url; do
	[[ -n "${id}" ]] || continue
	[[ "${id}" =~ ^[a-z0-9-]+$ && -n "${version}" && -n "${role}" ]] || {
		printf 'invalid capability source identity: %s\n' "${id}" >&2
		exit 1
	}
	[[ "${seen}" != *"|${id}|"* ]] || {
		printf 'duplicate capability source: %s\n' "${id}" >&2
		exit 1
	}
	seen+="${id}|"
	[[ "${status}" == pinned && "${digest}" =~ ^[0-9a-f]{64}$ &&
		"${bytes}" =~ ^[1-9][0-9]*$ && "${url}" == https://* ]] || {
		printf 'invalid capability source row: %s\n' "${id}" >&2
		exit 1
	}
	count=$((count + 1))
done < <(tail -n +2 "${manifest}")

[[ "${count}" -eq "${#required[@]}" ]] || {
	printf 'capability source count = %s, want %s\n' "${count}" "${#required[@]}" >&2
	exit 1
}
for id in "${required[@]}"; do
	[[ "${seen}" == *"|${id}|"* ]] || {
		printf 'missing capability source: %s\n' "${id}" >&2
		exit 1
	}
done

[[ "$(grep -Ec '^## CAPABILITY-DEC-[0-9]{3}:' "${register}")" -eq 11 ]] || {
	printf 'capability decision register must contain 11 decisions\n' >&2
	exit 1
}

cd "${root}"
GOWORK=off go test ./ -run \
	'^(TestHMACSHA256RFC4231Vector|TestEd25519RFC8032Vector|TestCanonicalPayloadHasOneStableRepresentation|TestVerifyURLRejectsAmbiguitySmugglingAndDowngrade|TestMemoryConsumptionIsAtomicAtTheUseLimit|TestVerificationChecksEveryRevocationBoundary|TestPythonHMACGoldenToken)$' \
	-count=1
python3 ./scripts/check-interoperability.py
