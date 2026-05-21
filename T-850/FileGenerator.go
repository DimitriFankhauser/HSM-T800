package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func generatePropertiesForQuarkus(pin string, label string) {
	var s string = ""
	s += "quarkus.security.security-providers=SunPKCS11 \n"
	s += "quarkus.security.security-provider-config.SunPKCS11=pkcs11.cfg \n"
	s += "quarkus.http.ssl.certificate.key-store-file=pkcs11.cfg\n"
	s += "quarkus.http.ssl.certificate.key-store-file-type=pkcs11 \n"
	s += fmt.Sprintf("quarkus.http.ssl.certificate.key-store-alias=%s \n", label)
	s += fmt.Sprintf("quarkus.http.ssl.certificate.key-store-password= %s  \n", pin)
	s += "quarkus.http.insecure-requests=disabled"

	wd, err := os.Getwd()
	check(err)

	path := filepath.Join(wd, "application.properties")
	err = os.WriteFile(path, []byte(s), 0644)
	check(err)
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}
func generateCfgForQuarkus(pathToSo string, slot string) {

	var s string

	s = "name = generated_by_t800 \n"
	s += fmt.Sprintf("library = %s\n", pathToSo)
	s += fmt.Sprintf("slot = %s\n", slot)

	wd, err := os.Getwd()
	check(err)

	path := filepath.Join(wd, "pkcs11.cfg")
	err = os.WriteFile(path, []byte(s), 0644)
	check(err)
}
