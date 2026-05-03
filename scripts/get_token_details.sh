#! /bin/bash
pkcs11-tool --module $1 --token-label $2 -O
