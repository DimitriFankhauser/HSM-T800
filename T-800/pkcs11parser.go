package main

import "strings"

func parsePKCS11Output(raw string) []PKCS11Object {
	var objects []PKCS11Object
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		if line == "" {
			continue
		}
		obj := PKCS11Object{}
		for _, pair := range strings.Split(line, "|") {
			kv := strings.SplitN(pair, "=", 2)
			if len(kv) != 2 {
				continue
			}
			switch kv[0] {
			case "object":
				obj.Object = kv[1]
			case "bits":
				obj.Bits = kv[1]
			case "label":
				obj.Label = kv[1]
			case "subject":
				obj.Subject = kv[1]
			case "serial":
				obj.Serial = kv[1]
			case "usage":
				obj.Usage = kv[1]
			case "access":
				obj.Access = kv[1]
			case "uri":
				obj.URI = kv[1]
			}
		}
		objects = append(objects, obj)
	}
	return objects
}
