.PHONY: clean test test-e2e deps build bootstrap-tools image

HACKDIR=./hack/bin
GORELEASER_CMD=$(HACKDIR)/goreleaser
ORG ?= ca-gip
VERSION=$(shell git rev-parse --short HEAD)

$(HACKDIR):
	mkdir -p $(HACKDIR)

bootstrap-tools: $(HACKDIR)
	command -v $(HACKDIR)/goreleaser || VERSION=v2.5.0 TMPDIR=$(HACKDIR) bash hack/goreleaser-install.sh
	# staticcheck is not required for the repository test target and the latest
	# release is not compatible with the Go toolchain used here, which causes the
	# CI bootstrap to fail before running any tests.
	chmod +x $(HACKDIR)/goreleaser

clean:
	rm -rf vendor build/*

build: bootstrap-tools deps
	ORG=${ORG} $(GORELEASER_CMD) release --clean --snapshot

deps:
	go mod tidy
	go mod vendor
	bash hack/update-codegen.sh
	go mod tidy
	go mod vendor

test: bootstrap-tools
	go test $$(go list ./... | grep -v /e2e) -coverprofile cover.out
#	staticcheck ./...

image: build

test-e2e: 
	go test ./test/e2e/ -v -ginkgo.v
