#!bin/bash

BASE_PATH="./internal/certs"

# First argument is the name of the certificate.
# Second argument is the key size.
# Third argument is the signing certificate.
# Fourth argument is the signing key.
generateCert() {
  openssl req -newkey rsa:$2 -noenc -keyout $BASE_PATH/$1-keypair.pem -x509 -days 365 \
    -CA $BASE_PATH/$3.pem -CAkey $BASE_PATH/$4.pem \
    -out $BASE_PATH/$1-cert.pem -subj "/CN=www.example.com" \
    -addext "subjectAltName=DNS:www.example.com"
  echo "Generated file: $BASE_PATH/$1-keypair.pem"

  openssl rsa -inform PEM -in $BASE_PATH/$1-keypair.pem -outform DER -out $BASE_PATH/$1-keypair.der
  echo "Generated file: $BASE_PATH/$1-keypair.der"
}

openssl genrsa -out $BASE_PATH/cakey.pem 4096
openssl req -new -x509 -days 1826 -key $BASE_PATH/cakey.pem -out $BASE_PATH/cacert.pem \
  -subj "/CN=www.example.com" -addext "subjectAltName=DNS:www.example.com"

# ======================================================================================================================
# Generate keys
# ======================================================================================================================

generateCert "2048b-rsa-example" 2048 "cacert" "cakey"
generateCert "4096b-rsa-example" 4096 "cacert" "cakey"

# ======================================================================================================================
# Generate Chain
# ======================================================================================================================

generateCert "chain-example-intermediate" 2048 "cacert" "cakey"
generateCert "chain-example-leaf" 2048 "chain-example-intermediate-cert" "chain-example-intermediate-keypair"
