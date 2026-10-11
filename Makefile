GOLIB ?= golib

.DEFAULT_GOAL := check

include verification/package.mk

.PHONY: check check-full ci cohesion inventory repository-check specification-check specification-check-online

check:
	$(GOLIB) check --local --all
	$(MAKE) conformance

check-full:
	$(GOLIB) check --all

ci:
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
