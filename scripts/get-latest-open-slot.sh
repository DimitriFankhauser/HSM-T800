#!/bin/bash
# returns the last number aka the number to create the new token
pkcs11-tool --module $1  --list-token-slots | grep -oP '(?<=Slot )\d+' | tail -1