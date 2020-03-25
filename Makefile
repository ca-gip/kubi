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
	 GOOS=linux GOARCH=amd64 go test ./internal/services ./internal/types ./internal/utils

test-only:
	@echo "-> Test only kubi operator binary"
	 GOOS=linux GOARCH=amd64 go test ./internal/services ./internal/types ./internal/utils

build: test
	@echo "-> Building kubi operator binary"
	GOOS=linux CGO_ENABLED=0 GOARCH=amd64 go build -a -ldflags '-extldflags "-static"' -v -o ./build/kubi -i $(GOPATH)/src/$(REPO)/cmd/main.go

