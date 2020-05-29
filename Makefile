.PHONY: clean

REPO= github.com/ca-gip/kubi
IMAGE= kubi
DOCKER_REPO= cagip

clean:
	rm -rf vendor build/kubi

dependency:
	go mod vendor

codegen: dependency
	bash hack/update-codegen.sh

test: codegen
	 GOARCH=amd64 go test ./internal/services ./pkg/types ./internal/utils

test-only:
	@echo "-> Test only kubi operator binary"
	GOARCH=amd64 go test ./internal/services ./pkg/types ./internal/utils

build: test
	@echo "-> Building kubi operator binary"
	CGO_ENABLED=0 GOARCH=amd64 go build -a -ldflags '-extldflags "-static"' -v -o ./build/kubi -i $(GOPATH)/src/$(REPO)/cmd/main.go

