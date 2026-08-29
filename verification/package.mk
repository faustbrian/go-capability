.PHONY: clean-consumer conformance interoperability

clean-consumer:
	./scripts/check-clean-consumer.sh

conformance:
	./scripts/check-conformance.sh

interoperability:
	python3 ./scripts/check-interoperability.py
