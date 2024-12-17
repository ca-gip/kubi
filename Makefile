.PHONY: clean test deps build build-operator build-auth bootstrap-tools

HACKDIR=./hack/bin
GORELEASER_CMD=$(HACKDIR)/goreleaser
ORG ?= ca-gip
VERSION=$(shell git rev-parse --short HEAD)

$(HACKDIR):
	mkdir -p $(HACKDIR)

bootstrap-tools: $(HACKDIR)
	command -v $(HACKDIR)/goreleaser || VERSION=v1.24.0 TMPDIR=$(HACKDIR) bash hack/goreleaser-install.sh
	command -v staticcheck || go install honnef.co/go/tools/cmd/staticcheck@latest
	chmod +x $(HACKDIR)/goreleaser

clean:
	rm -rf vendor build/*

build: bootstrap-tools deps
	ORG=${ORG} $(GORELEASER_CMD) build --clean --snapshot

deps:
	go mod tidy
	go mod vendor
	bash hack/update-codegen.sh
	go mod tidy

test: bootstrap-tools
	go test ./...
	staticcheck ./...

image:
	ORG=${ORG} $(GORELEASER_CMD) release --clean --snapshot
