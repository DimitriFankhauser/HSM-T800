#! /bin/bash

pkcs11-tool --module  $1 \
  --verify \
  --mechanism SHA256-RSA-PKCS-PSS \
  --token-label $2 \
  --label $3 \
  --input-file $4 \
  --signature-file ./signature.txt \
