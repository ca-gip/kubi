#!/usr/bin/env bash

# Generate API stub, clientSet and crds
./vendor/k8s.io/code-generator/generate-groups.sh all "github.com/ca-gip/kubi/pkg/client" "github.com/ca-gip/kubi/pkg/apis" ca-gip:v1


go build -o bin/kubi
