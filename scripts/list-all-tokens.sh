# /bin/bash 
pkcs11-tool --module /lib64/softhsm/libsofthsm.so --list-token-slots | awk '
/^Slot [0-9]+/ {
    match($0, /Slot ([0-9]+) \(([^)]+)\)/, arr)
    slot = arr[1]
}
/token label/ {
    split($0, a, ": ")
    print slot,a[2]
}
'