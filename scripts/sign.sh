#! /bin/bash

pkcs11-tool --module  $1 \
  --sign \
  --mechanism SHA256-RSA-PKCS-PSS \
  --token-label $2 \
  --label $3 \
  --input-file $4 \
  --pin $5 \
  --output-file ./signature.txt

base64 ./signature.txt