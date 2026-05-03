#! /bin/bash
pkcs11-tool --module  $1 \
  --encrypt \
  --mechanism RSA-PKCS \
  --token-label $2 \
  --label $3 \
  --input-file $4 \
  --pin $5 \
  --output-file ./encrypted.bin