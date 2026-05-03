#! /bin/bash

pkcs11-tool  --module $1 --token-label $2 -O --pin $3 | awk '
/Object;/ {
    if (obj != "") print_obj()
    obj = $0
    label = subject = serial = usage = access = bits = uri = ""
}
/label:/ && !/subject:/ { label = $2 }
/subject:/ { subject = substr($0, index($0,"DN:")) }
/serial:/ { serial = $2 }
/RSA|EC/ { match($0, /[0-9]+ bits/); bits = substr($0, RSTART, RLENGTH) }
/Usage:/ { usage = substr($0, index($0,$2)) }
/Access:/ { access = substr($0, index($0,$2)) }
/uri:/ { uri = $2 }

function print_obj() {
    printf "object=%s", obj
    if (bits)    printf "|bits=%s", bits
    if (label)   printf "|label=%s", label
    if (subject) printf "|subject=%s", subject
    if (serial)  printf "|serial=%s", serial
    if (usage)   printf "|usage=%s", usage
    if (access)  printf "|access=%s", access
    if (uri)     printf "|uri=%s", uri
    printf "\n"
}

END { if (obj != "") print_obj() }
'