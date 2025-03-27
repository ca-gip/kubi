#!/bin/bash

# Define CFSSL version
VERSION=$(curl --silent "https://api.github.com/repos/cloudflare/cfssl/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
VNUMBER=${VERSION#"v"}

# Define where we want to store the binaries
CFSSL_DIR="/opt/cfssl"  # Directory to store CFSSL binaries

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "Docker is not installed. Please install Docker first."
    exit 1
fi

# Create the directory to store CFSSL binaries if it doesn't exist
sudo mkdir -p "$CFSSL_DIR"

# Pull CFSSL Docker image
docker pull cloudflare/cfssl

# Run CFSSL inside a Docker container to download and store binaries in /opt/cfssl
docker run --rm -v "$CFSSL_DIR":/cfssl cloudflare/cfssl \
    sh -c "wget https://github.com/cloudflare/cfssl/releases/download/${VERSION}/cfssljson_${VNUMBER}_linux_amd64 -O /cfssl/cfssljson && \
           chmod +x /cfssl/cfssljson && \
           wget https://github.com/cloudflare/cfssl/releases/download/${VERSION}/cfssl_${VNUMBER}_linux_amd64 -O /cfssl/cfssl && \
           chmod +x /cfssl/cfssl && \
           cfssljson -version && \
           /cfssl/cfssl -version"

# Inform the user of the installation path for CFSSL binaries
echo "CFSSL binaries have been downloaded and stored at: $CFSSL_DIR"
