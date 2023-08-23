#!/bin/bash
set -euxo pipefail
shopt -s inherit_errexit

# This script will do a full bootstrap with the correct options for a local dev setup
# Just enter the requested password for the certificates, when you are asked for them.

# cleanup
rm -rf tls/*

# full bootstrap with general server certificate
# you can execute this, or the individual steps below for more customization
#cargo run -- x509 \
#  --o 'My Org' \
#  --alt-name-dns localhost \
#  --usages digital-signature \
#  --usages-ext server-auth \
#  --stage full \
#  --clean

# Root CA only
cargo run x509 \
  --cn 'Nioca' \
  --c 'DE' \
  --l 'Dusseldorf' \
  --o 'My Org' \
  --st 'NRW' \
  --stage root \
  --clean

# Intermediate CA only
cargo run x509 \
  --cn 'Nioca IT' \
  --c 'DE' \
  --l 'Dusseldorf' \
  --ou 'My Org - CA' \
  --o 'My Org' \
  --st 'NRW' \
  --stage intermediate

# EndEntity only
#cargo run x509 \
#  --cn 'ca.test.de' \
#  --c 'DE' \
#  --l 'Dusseldorf' \
#  --o 'My Org' \
#  --st 'NRW' \
#  --alt-name-ip '192.168.14.50' \
#  --alt-name-dns 'ca.test.de' \
#  --usages-ext server-auth \
#  --usages-ext client-auth \
#  --stage end-entity

# create an additional certificate only valid for the unsealing
cargo run x509 \
  --alt-name-uri 'localhost:8080/unseal' \
  --alt-name-uri 'localhost:8443/unseal' \
  --alt-name-uri '192.168.14.50:8080/unseal' \
  --alt-name-uri '192.168.14.50:8443/unseal' \
  --usages digital-signature \
  --usages-ext server-auth \
  --o 'My Org' \
  --stage end-entity

# root cert chain
cp ca/x509/intermediate/ca-chain.pem tls/ca-chain.pem
# server cert for unsealing
cp ca/x509/end_entity/1/cert.pem tls/unseal.cert.pem
cp ca/x509/end_entity/1/key.pem tls/unseal.key.pem

cat tls/ca-chain.pem >> tls/unseal.cert.pem

chmod 0600 tls/*key*
