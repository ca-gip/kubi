.PHONY: clean test deps build bootstrap-tools image

HACKDIR=./hack/bin
GORELEASER_CMD=$(HACKDIR)/goreleaser
ORG ?= ca-gip
VERSION=$(shell git rev-parse --short HEAD)

$(HACKDIR):
	mkdir -p $(HACKDIR)

bootstrap-tools: $(HACKDIR)
	command -v $(HACKDIR)/goreleaser || VERSION=v2.5.0 TMPDIR=$(HACKDIR) bash hack/goreleaser-install.sh
	command -v staticcheck || go install honnef.co/go/tools/cmd/staticcheck@latest
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

test: bootstrap-tools
	go test ./...
	staticcheck ./...

image: build
