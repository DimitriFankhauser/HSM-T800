#! /bin/bash

pkcs11-tool --module $1 --init-token --slot $2 --label $3 --so-pin $4

#pkcs11-tool --module /lib64/softhsm/libsofthsm.so --init-token --slot 20 --label "IhopeThisWorks"