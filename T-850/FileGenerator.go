package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func generatePropertiesForQuarkus(pin string, label string) error {
	var s string = ""
	s += "quarkus.security.security-providers=SunPKCS11 \n"
	s += "quarkus.security.security-provider-config.SunPKCS11=pkcs11.cfg \n"
	s += "quarkus.http.ssl.certificate.key-store-file=pkcs11.cfg\n"
	s += "quarkus.http.ssl.certificate.key-store-file-type=pkcs11 \n"
	s += fmt.Sprintf("quarkus.http.ssl.certificate.key-store-alias=%s \n", label)
	s += fmt.Sprintf("quarkus.http.ssl.certificate.key-store-password= %s  \n", pin)
	s += "quarkus.http.insecure-requests=disabled \n"

	s += "#uncomment the following lines for mTLS\n"
	s += "#quarkus.http.ssl.certificate.trust-store-file=none \n"
	s += "#quarkus.http.ssl.certificate.trust-store-file-type=PKCS11\n"
	s += fmt.Sprintf("#quarkus.http.ssl.certificate.trust-store-password=%s \n", pin)
	s += fmt.Sprintf("#quarkus.http.ssl.certificate.trust-store-cert-alias=%s \n", label)
	s += "#quarkus.http.ssl.client-auth=REQUIRED\n"

	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("generatePropertiesForQuarkus: getting working directory: %v", err)
	}

	path := filepath.Join(wd, "application.properties")
	if err = os.WriteFile(path, []byte(s), 0644); err != nil {
		return fmt.Errorf("generatePropertiesForQuarkus: writing file: %v", err)
	}
	return nil
}

func generateCfgForQuarkus(pathToSo string, slot string) error {
	var s string

	s = "name = generated_by_t800 \n"
	s += fmt.Sprintf("library = %s\n", pathToSo)
	s += fmt.Sprintf("slot = %s\n", slot)

	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("generateCfgForQuarkus: getting working directory: %v", err)
	}

	path := filepath.Join(wd, "pkcs11.cfg")
	if err = os.WriteFile(path, []byte(s), 0644); err != nil {
		return fmt.Errorf("generateCfgForQuarkus: writing file: %v", err)
	}
	return nil
}
