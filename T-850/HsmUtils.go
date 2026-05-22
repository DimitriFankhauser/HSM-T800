package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"

	"github.com/ThalesGroup/crypto11"
	"github.com/miekg/pkcs11"
)

// Source - https://stackoverflow.com/a/22467409
// Posted by user3431012, modified by community. See post 'Timeline' for change history
// Retrieved 2026-05-20, License - CC BY-SA 4.0

func checkFileExists(filePath string) bool {
	if !strings.HasSuffix(filePath, ".so") {
		return false
	}

	_, error := os.Stat(filePath)
	if error != nil {
		return false
	}
	return true
}

func importCertForKeyPair(ctx *crypto11.Context, kp crypto11.Signer, certPath string) {
	attr, err := ctx.GetAttribute(kp, crypto11.CkaId)
	if err != nil || attr == nil {
		log.Fatalf("importCertForKeyPair: getting key ID: %v", err)
	}
	ImportCert(ctx, attr.Value, certPath)
}

func deleteKeyPair(ctx *crypto11.Context, kp crypto11.Signer) {
	kp.Delete()
}
func deleteCertificate(ctx *crypto11.Context, cert tls.Certificate) {
	err := ctx.DeleteCertificate(nil, nil, cert.Leaf.SerialNumber)
	if err != nil {
		log.Fatalf("Serial Number doesn't match. Can't delete certificate: %v", err)
	}
}
func exportCertificate(ctx *crypto11.Context, cert tls.Certificate) {
	f, err := os.Create("certificate.pem")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	pem.Encode(f, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Leaf.Raw,
	})
}

func generateCSR(cert tls.Certificate) {
	template := &x509.CertificateRequest{
		Subject:        cert.Leaf.Subject,
		DNSNames:       cert.Leaf.DNSNames,
		IPAddresses:    cert.Leaf.IPAddresses,
		EmailAddresses: cert.Leaf.EmailAddresses,
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, template, cert.PrivateKey)
	if err != nil {
		log.Fatalf("generateCSR: creating CSR: %v", err)
	}
	f, err := os.Create("csr.pem")
	if err != nil {
		log.Fatalf("generateCSR: creating file: %v", err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes}); err != nil {
		log.Fatalf("generateCSR: encoding PEM: %v", err)
	}
}

func exportPublicKey(ctx *crypto11.Context, kp crypto11.Signer) {
	f, err := os.Create("public.pem")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	publicKey := kp.Public()
	pkixBytes, _ := x509.MarshalPKIXPublicKey(publicKey)

	pem.Encode(f, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pkixBytes,
	})
}

func initializeCtx(m *model) {
	ctx, err := crypto11.Configure(&crypto11.Config{
		Path:       m.pathToSo,
		TokenLabel: m.tokenLabel,
		Pin:        m.pin,
	})
	if err != nil {
		ctx = nil
		log.Fatal(err)
	} else {
		m.ctx = ctx
	}
}

func getKeyPairs(ctx *crypto11.Context) []crypto11.Signer {
	if ctx == nil {
		return nil
	} else {
		keyPairs, err := ctx.FindAllKeyPairs()
		if err != nil {
			log.Fatalf("FindAllKeyPairs: %v", err)
		}
		return keyPairs
	}

}

func getCertificates(ctx *crypto11.Context) []tls.Certificate {
	if ctx == nil {
		return nil
	}
	certs, err := ctx.FindAllPairedCertificates()
	if err != nil {
		log.Fatalf("FindAllPairedCertificates: %v", err)
	}
	return certs
}

func LoadX509KeyPair(certFile, keyFile string) (*x509.Certificate, interface{}) {
	cf, e := os.ReadFile(certFile)
	if e != nil {
		fmt.Println("cfload:", e.Error())
		os.Exit(1)
	}

	kf, e := os.ReadFile(keyFile)
	if e != nil {
		fmt.Println("kfload:", e.Error())
		os.Exit(1)
	}
	cpb, cr := pem.Decode(cf)
	fmt.Println(string(cr))
	kpb, kr := pem.Decode(kf)
	fmt.Println(string(kr))
	crt, e := x509.ParseCertificate(cpb.Bytes)
	if e != nil {
		fmt.Println("parsex509:", e.Error())
		os.Exit(1)
	}

	var key interface{}
	// Try PKCS8 first, then PKCS1, then EC
	key, e = x509.ParsePKCS8PrivateKey(kpb.Bytes)
	if e != nil {
		key, e = x509.ParsePKCS1PrivateKey(kpb.Bytes)
		if e != nil {
			key, e = x509.ParseECPrivateKey(kpb.Bytes)
			if e != nil {
				fmt.Println("parsekey: could not parse key as PKCS8, PKCS1 or EC")
				os.Exit(1)
			}
		}
	}
	return crt, key
}

func ImportCert(ctx *crypto11.Context, id []byte, certPath string) {
	if ctx == nil {
		log.Fatal("ctx is nil")
	}
	raw, err := os.ReadFile(certPath)
	if err != nil {
		log.Fatalf("ImportCert: reading %s: %v", certPath, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		log.Fatalf("ImportCert: no PEM block found in %s", certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("ImportCert: parsing certificate: %v", err)
	}
	if err := ctx.ImportCertificate(id, cert); err != nil {
		log.Fatalf("ImportCert: importing to HSM: %v", err)
	}
}

func importKeyPair(pathToSo, tokenLabel, pin string, key interface{}, id []byte, label string) error {
	p := pkcs11.New(pathToSo)
	err := p.Initialize()
	if err != nil && err != pkcs11.Error(pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
		return err
	}
	alreadyInitialized := err == pkcs11.Error(pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED)
	defer p.Destroy()
	if !alreadyInitialized {
		defer p.Finalize()
	}

	slots, err := p.GetSlotList(true)
	if err != nil {
		return err
	}

	var slot uint
	found := false
	for _, s := range slots {
		info, err := p.GetTokenInfo(s)
		if err == nil && strings.TrimRight(info.Label, " ") == tokenLabel {
			slot = s
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("token %q not found", tokenLabel)
	}

	session, err := p.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return err
	}
	defer p.CloseSession(session)

	if err := p.Login(session, pkcs11.CKU_USER, pin); err != nil {
		if err != pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
			return err
		}
	}
	defer p.Logout(session)

	switch k := key.(type) {
	case *rsa.PrivateKey:
		if _, err := importRSAPrivateKey(p, session, k, id, label); err != nil {
			return fmt.Errorf("importing RSA private key: %w", err)
		}
		if _, err := importRSAPublicKey(p, session, k, id, label); err != nil {
			return fmt.Errorf("importing RSA public key: %w", err)
		}
	case *ecdsa.PrivateKey:
		if _, err := importECPrivateKey(p, session, k, id, label); err != nil {
			return fmt.Errorf("importing EC private key: %w", err)
		}
		if _, err := importECPublicKey(p, session, k, id, label); err != nil {
			return fmt.Errorf("importing EC public key: %w", err)
		}
	default:
		return fmt.Errorf("unsupported key type: %T", key)
	}

	return nil
}

func importRSAPrivateKey(p *pkcs11.Ctx, session pkcs11.SessionHandle, rsaKey *rsa.PrivateKey, id []byte, label string) (pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, rsaKey.N.Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, big.NewInt(int64(rsaKey.E)).Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE_EXPONENT, rsaKey.D.Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_PRIME_1, rsaKey.Primes[0].Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_PRIME_2, rsaKey.Primes[1].Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_EXPONENT_1, rsaKey.Precomputed.Dp.Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_EXPONENT_2, rsaKey.Precomputed.Dq.Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_COEFFICIENT, rsaKey.Precomputed.Qinv.Bytes()),
	}
	return p.CreateObject(session, template)
}

func importRSAPublicKey(p *pkcs11.Ctx, session pkcs11.SessionHandle, rsaKey *rsa.PrivateKey, id []byte, label string) (pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, rsaKey.N.Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, big.NewInt(int64(rsaKey.E)).Bytes()),
	}
	return p.CreateObject(session, template)
}

// ecCurveOID returns the DER-encoded OID for the given elliptic curve,
// which is what PKCS#11 expects for CKA_EC_PARAMS.
func ecCurveOID(curve elliptic.Curve) ([]byte, error) {
	var oid asn1.ObjectIdentifier
	switch curve {
	case elliptic.P224():
		oid = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	case elliptic.P256():
		oid = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	case elliptic.P384():
		oid = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	case elliptic.P521():
		oid = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
	default:
		return nil, fmt.Errorf("unsupported elliptic curve: %s", curve.Params().Name)
	}
	return asn1.Marshal(oid)
}

func importECPrivateKey(p *pkcs11.Ctx, session pkcs11.SessionHandle, ecKey *ecdsa.PrivateKey, id []byte, label string) (pkcs11.ObjectHandle, error) {
	oid, err := ecCurveOID(ecKey.Curve)
	if err != nil {
		return 0, err
	}

	// CKA_VALUE for EC private key is the raw big-endian private scalar
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_ECDSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, oid),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, ecKey.D.Bytes()),
	}
	return p.CreateObject(session, template)
}

func importECPublicKey(p *pkcs11.Ctx, session pkcs11.SessionHandle, ecKey *ecdsa.PrivateKey, id []byte, label string) (pkcs11.ObjectHandle, error) {
	oid, err := ecCurveOID(ecKey.Curve)
	if err != nil {
		return 0, err
	}

	// CKA_EC_POINT must be the DER-encoded uncompressed point: 04 || X || Y
	ecPoint, err := asn1.Marshal(elliptic.Marshal(ecKey.Curve, ecKey.PublicKey.X, ecKey.PublicKey.Y))
	if err != nil {
		return 0, fmt.Errorf("marshaling EC point: %w", err)
	}

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_ECDSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, oid),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, ecPoint),
	}
	return p.CreateObject(session, template)
}
