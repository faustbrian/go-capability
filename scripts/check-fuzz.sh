#!/usr/bin/env bash
set -euo pipefail

fuzz_time="${FUZZ_TIME:-10000x}"
for target in \
    FuzzParseNeverAcceptsTwoPayloadRepresentations \
    FuzzSignedURLRoundTripIsDeterministic \
    FuzzParseTokenIsBounded
do
    cache="$(mktemp -d "${TMPDIR:-/tmp}/capability-gocache.fuzz.XXXXXX")"
    cleanup() {
        rm -rf -- "${cache}"
    }
    trap cleanup EXIT HUP INT TERM
    GOCACHE="${cache}" GOWORK=off go test ./ -run '^$' -fuzz="^${target}$" \
        -fuzztime="${fuzz_time}" -parallel=4 -timeout=2m
    cleanup
    trap - EXIT HUP INT TERM
done
