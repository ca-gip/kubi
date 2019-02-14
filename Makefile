.PHONY: all

REPO= github.com/ca-gip/kubi
IMAGE= kubi
TAG= dev
DOCKER_REPO= cagip



build:
	vendor/k8s.io/code-generator/generate-groups.sh all "$(REPO)/pkg/client" "$(REPO)/pkg/apis" ca-gip:v1
	go build -v -o ./build/kubi -i $(GOPATH)/src/$(REPO)/cmd/main.go

darwin:
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 vendor/k8s.io/code-generator/generate-groups.sh all "$(REPO)/pkg/client" "$(REPO)/pkg/apis" ca-gip:v1
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s" -v -o ./build/kubi -i $(GOPATH)/src/$(REPO)/cmd/main.go

linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 vendor/k8s.io/code-generator/generate-groups.sh all "$(REPO)/pkg/client" "$(REPO)/pkg/apis" ca-gip:v1
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s" -v -o ./build/kubi -i $(GOPATH)/src/$(REPO)/cmd/main.go

release:
	docker build -t "$(DOCKER_REPO)/$(IMAGE):$(TAG)" .
	docker push "$(DOCKER_REPO)/$(IMAGE):$(TAG)"

test:
	 go test ./internal/services ./internal/types ./internal/utils

dep:
	glide install

