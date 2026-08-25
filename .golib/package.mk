GO ?= go
FUZZ_TIME ?= 10000x
BENCH_TIME ?= 100ms

.PHONY: api benchmark check clean-consumer conformance coverage docs format-check \
	fuzz interoperability mutation race test tidy-check vet

format-check:
	test -z "$$(gofmt -l .)"

tidy-check:
	GOWORK=off $(GO) mod tidy -diff

vet:
	GOWORK=off $(GO) vet ./...

test:
	GOWORK=off $(GO) test ./... -count=1

coverage:
	../../scripts/check-coverage.sh .

race:
	GOWORK=off $(GO) test -race ./... -count=1

fuzz:
	FUZZ_TIME=$(FUZZ_TIME) ./scripts/check-fuzz.sh

mutation:
	../../scripts/check-mutation.sh .

benchmark:
	GOWORK=off $(GO) test ./... -run '^$$' -bench . -benchmem -benchtime=$(BENCH_TIME)

docs:
	GOWORK=off $(GO) test ./... -run '^Example' -count=1

api:
	../../scripts/check-api-baseline.sh .

conformance:
	./scripts/check-conformance.sh

interoperability:
	python3 ./scripts/check-interoperability.py

clean-consumer:
	./scripts/check-clean-consumer.sh

check: format-check tidy-check vet test coverage race fuzz docs api \
	conformance interoperability benchmark clean-consumer
