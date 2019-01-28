HUB :=
REPO := github.com/ca-gip/kubi
IMAGE := kubi
TAG := dev

build:
	go build -i -o kubi $(GOPATH)/src/$(REPO)/main.go

darwin:
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s" -o kubi  $(GOPATH)/src/$(REPO)/main.go

linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s" -o kubi  $(GOPATH)/src/$(REPO)/main.go

release:
	docker build -t "$(REPO)/$(IMAGE):$(TAG)" .
	docker push "$(REPO)/$(IMAGE):$(TAG)"

test: 
	go test  $(shell go list ./... | grep -v fake)

dep:
	glide up

.PHONY: build test darwin image e2e clean-test