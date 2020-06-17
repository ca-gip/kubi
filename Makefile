.PHONY: clean

REPO= github.com/ca-gip/kubi
IMAGE= kubi
DOCKER_REPO= cagip

clean:
	rm -rf vendor build/*

dependency:
	go mod vendor

codegen: dependency
	bash hack/update-codegen.sh

test: codegen
	 GOARCH=amd64 go test ./internal/services ./pkg/types ./internal/utils

test-only:
	@echo "-> Test only kubi operator binary"
	GOARCH=amd64 go test ./internal/services ./pkg/types ./internal/utils

build-operator: test
	@echo "-> Building kubi operator"
	CGO_ENABLED=0 GOARCH=amd64 go build -a -ldflags '-extldflags "-static"' -v -o ./build/kubi-operator -i $(GOPATH)/src/$(REPO)/cmd/operator/main.go

build-api: test
	@echo "-> Building kubi api"
	CGO_ENABLED=0 GOARCH=amd64 go build -a -ldflags '-extldflags "-static"' -v -o ./build/kubi-api -i $(GOPATH)/src/$(REPO)/cmd/api/main.go

build-webhook: test
	@echo "-> Building kubi authorization webhook"
	CGO_ENABLED=0 GOARCH=amd64 go build -a -ldflags '-extldflags "-static"' -v -o ./build/kubi-webhook -i $(GOPATH)/src/$(REPO)/cmd/authorization-webhook/main.go

build: build-webhook build-operator build-api


