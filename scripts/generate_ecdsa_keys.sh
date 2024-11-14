#!/bin/bash

# Create a temporary directory using mktemp
TEMP_DIR=$(mktemp -d)

# Check if mktemp succeeded
if [[ ! -d "$TEMP_DIR" ]]; then
    echo "Error: Failed to create a temporary directory."
    exit 1
fi

# Generate the ECDSA private key using secp521r1 and store it in the temp directory
KEY_FILE="${TEMP_DIR}/ecdsa-key.pem"
openssl ecparam -genkey -name secp521r1 -noout -out "$KEY_FILE"

# Check if the key generation was successful
if [[ $? -ne 0 ]]; then
    echo "Error: Failed to generate the private key."
    exit 1
fi

# Generate the corresponding ECDSA public key from the private key
PUB_KEY_FILE="${TEMP_DIR}/ecdsa-public.pem"
openssl ec -in "$KEY_FILE" -pubout -out "$PUB_KEY_FILE"

# Check if the public key generation was successful
if [[ $? -ne 0 ]]; then
    echo "Error: Failed to generate the public key."
    exit 1
fi

# Inform the user about the location of the generated keys
echo "ECDSA private key has been generated and stored at: $KEY_FILE"
echo "ECDSA public key has been generated and stored at: $PUB_KEY_FILE"

exit 0
