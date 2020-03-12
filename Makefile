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

build: test
	@echo "-> Building kubi operator binary"
	GOOS=linux GOARCH=amd64 go build -v -o ./build/kubi -i $(GOPATH)/src/$(REPO)/cmd/main.go

