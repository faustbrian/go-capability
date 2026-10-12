GOLIB ?= golib

.DEFAULT_GOAL := check

include verification/package.mk

.PHONY: source-docs-check check check-full ci cohesion inventory repository-check specification-check specification-check-online

check: source-docs-check
	$(GOLIB) check --local --all
	$(MAKE) conformance

check-full: source-docs-check
	$(GOLIB) check --all

ci: source-docs-check
	$(GOLIB) repository check
	$(GOLIB) cohesion check
	$(GOLIB) check --local --all
	$(MAKE) conformance

specification-check:
	$(GOLIB) specification check

specification-check-online:
	$(GOLIB) specification check --online

cohesion:
	$(GOLIB) cohesion check

inventory repository-check:
	$(GOLIB) repository check

source-docs-check:
	$(GOLIB) source-docs check
