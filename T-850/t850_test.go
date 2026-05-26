package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ThalesGroup/crypto11"
)

// mockSigner implements crypto11.Signer without touching the HSM.
type mockSigner struct {
	pub crypto.PublicKey
	sig []byte
	err error
}

func (m *mockSigner) Public() crypto.PublicKey { return m.pub }
func (m *mockSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return m.sig, m.err
}
func (m *mockSigner) Delete() error            { return nil }

var _ crypto11.Signer = (*mockSigner)(nil)

// ────────────────────────────────────────────────────────────
// cursorUp / cursorDown
// ────────────────────────────────────────────────────────────

func TestCursorUp(t *testing.T) {
	cases := []struct{ in, want int }{
		{5, 4},
		{1, 0},
		{0, 0}, // clamped at zero
	}
	for _, c := range cases {
		if got := cursorUp(c.in); got != c.want {
			t.Errorf("cursorUp(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestCursorDown(t *testing.T) {
	cases := []struct{ cursor, max, want int }{
		{0, 5, 1},
		{4, 5, 5},
		{5, 5, 5}, // clamped at max
		{3, 3, 3},
	}
	for _, c := range cases {
		if got := cursorDown(c.cursor, c.max); got != c.want {
			t.Errorf("cursorDown(%d,%d) = %d, want %d", c.cursor, c.max, got, c.want)
		}
	}
}

// ────────────────────────────────────────────────────────────
// isValidLabel
// ────────────────────────────────────────────────────────────

func TestIsValidLabel(t *testing.T) {
	valid := []string{
		"myKey",
		"my_key",
		"my-key",
		"Key123",
		"A",
		"_",
		"-",
		"",       // empty string — loop never runs, returns true
		"abc123", // alphanumeric
	}
	for _, s := range valid {
		if !isValidLabel(s) {
			t.Errorf("isValidLabel(%q) = false, want true", s)
		}
	}

	invalid := []string{
		"my key",
		"my.key",
		"my/key",
		"my@key",
		"!key",
		"key$",
		"key name",
	}
	for _, s := range invalid {
		if isValidLabel(s) {
			t.Errorf("isValidLabel(%q) = true, want false", s)
		}
	}
}

// ────────────────────────────────────────────────────────────
// newHasher
// ────────────────────────────────────────────────────────────

func TestNewHasher_SupportedAlgos(t *testing.T) {
	cases := []struct {
		algo     crypto.Hash
		wantSize int
	}{
		{crypto.SHA256, 32},
		{crypto.SHA384, 48},
		{crypto.SHA512, 64},
	}
	for _, c := range cases {
		h, err := newHasher(c.algo)
		if err != nil {
			t.Errorf("newHasher(%v): unexpected error: %v", c.algo, err)
			continue
		}
		if h == nil {
			t.Errorf("newHasher(%v): got nil hasher", c.algo)
			continue
		}
		if h.Size() != c.wantSize {
			t.Errorf("newHasher(%v): digest size = %d, want %d", c.algo, h.Size(), c.wantSize)
		}
	}
}

func TestNewHasher_UnsupportedAlgo(t *testing.T) {
	unsupported := []crypto.Hash{crypto.MD5, crypto.SHA1, crypto.SHA224}
	for _, algo := range unsupported {
		h, err := newHasher(algo)
		if err == nil {
			t.Errorf("newHasher(%v): expected error, got nil", algo)
		}
		if h != nil {
			t.Errorf("newHasher(%v): expected nil hasher on error", algo)
		}
	}
}

// ────────────────────────────────────────────────────────────
// ecCurveOID
// ────────────────────────────────────────────────────────────

func TestEcCurveOID_KnownCurves(t *testing.T) {
	// Expected OIDs per RFC 5480 / SEC 2
	cases := []struct {
		curve   elliptic.Curve
		wantOID asn1.ObjectIdentifier
	}{
		{elliptic.P224(), asn1.ObjectIdentifier{1, 3, 132, 0, 33}},
		{elliptic.P256(), asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}},
		{elliptic.P384(), asn1.ObjectIdentifier{1, 3, 132, 0, 34}},
		{elliptic.P521(), asn1.ObjectIdentifier{1, 3, 132, 0, 35}},
	}
	for _, c := range cases {
		b, err := ecCurveOID(c.curve)
		if err != nil {
			t.Errorf("ecCurveOID(%s): unexpected error: %v", c.curve.Params().Name, err)
			continue
		}
		var got asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(b, &got); err != nil {
			t.Errorf("ecCurveOID(%s): ASN1 unmarshal error: %v", c.curve.Params().Name, err)
			continue
		}
		if !got.Equal(c.wantOID) {
			t.Errorf("ecCurveOID(%s): got %v, want %v", c.curve.Params().Name, got, c.wantOID)
		}
	}
}

func TestEcCurveOID_ReturnsDEREncoded(t *testing.T) {
	// The raw bytes must be valid DER (not just a raw OID).
	b, err := ecCurveOID(elliptic.P256())
	if err != nil {
		t.Fatal(err)
	}
	if len(b) == 0 {
		t.Fatal("ecCurveOID returned empty bytes")
	}
	// DER-encoded OIDs start with tag 0x06
	if b[0] != 0x06 {
		t.Errorf("expected DER OID tag 0x06, got 0x%02x", b[0])
	}
}

// ────────────────────────────────────────────────────────────
// checkFileExists
// ────────────────────────────────────────────────────────────

func TestCheckFileExists_ExistingSOFile(t *testing.T) {
	f, err := os.CreateTemp("", "libtest-*.so")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	defer os.Remove(f.Name())

	if !checkFileExists(f.Name()) {
		t.Errorf("checkFileExists(%q) = false, want true", f.Name())
	}
}

func TestCheckFileExists_WrongExtension(t *testing.T) {
	f, err := os.CreateTemp("", "libtest-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	defer os.Remove(f.Name())

	if checkFileExists(f.Name()) {
		t.Errorf("checkFileExists(%q) = true, want false (not a .so file)", f.Name())
	}
}

func TestCheckFileExists_NonExistentFile(t *testing.T) {
	if checkFileExists("/nonexistent/path/lib.so") {
		t.Error("checkFileExists on non-existent path should return false")
	}
}

func TestCheckFileExists_NoExtension(t *testing.T) {
	if checkFileExists("/usr/lib/somelib") {
		t.Error("checkFileExists without .so extension should return false")
	}
}

// ────────────────────────────────────────────────────────────
// generatePropertiesForQuarkus
// ────────────────────────────────────────────────────────────

func TestGeneratePropertiesForQuarkus(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	pin := "mypin123"
	label := "myTLSKey"
	if err := generatePropertiesForQuarkus(pin, label); err != nil {
		t.Fatalf("generatePropertiesForQuarkus: %v", err)
	}

	content, err := os.ReadFile(filepath.Join(dir, "application.properties"))
	if err != nil {
		t.Fatalf("reading application.properties: %v", err)
	}
	s := string(content)

	checks := []string{
		"SunPKCS11",
		"pkcs11.cfg",
		label,
		pin,
		"quarkus.http.insecure-requests=disabled",
		"quarkus.http.ssl.certificate.key-store-file-type=pkcs11",
	}
	for _, want := range checks {
		if !strings.Contains(s, want) {
			t.Errorf("application.properties missing %q", want)
		}
	}
}

// ────────────────────────────────────────────────────────────
// generateCfgForQuarkus
// ────────────────────────────────────────────────────────────

func TestGenerateCfgForQuarkus(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	pathToSo := "/usr/lib/opensc-pkcs11.so"
	slot := "0"
	if err := generateCfgForQuarkus(pathToSo, slot); err != nil {
		t.Fatalf("generateCfgForQuarkus: %v", err)
	}

	content, err := os.ReadFile(filepath.Join(dir, "pkcs11.cfg"))
	if err != nil {
		t.Fatalf("reading pkcs11.cfg: %v", err)
	}
	s := string(content)

	if !strings.Contains(s, "generated_by_t800") {
		t.Error("pkcs11.cfg missing 'name = generated_by_t800'")
	}
	if !strings.Contains(s, pathToSo) {
		t.Errorf("pkcs11.cfg missing library path %q", pathToSo)
	}
	if !strings.Contains(s, "slot = "+slot) {
		t.Errorf("pkcs11.cfg missing 'slot = %s'", slot)
	}
}

// ────────────────────────────────────────────────────────────
// navigationMax
// ────────────────────────────────────────────────────────────

// makeNavModel builds a minimal model suitable for navigationMax tests.
func makeNavModel(selectedMode int, modeSteps map[int]int, keyPairCount, certCount int) model {
	m := model{
		selectedMode: selectedMode,
		modes:        make([]Mode, 6),
		keyPairs:     make([]crypto11.Signer, keyPairCount),
		certificates: make([]tls.Certificate, certCount),
	}
	for idx, step := range modeSteps {
		m.modes[idx].Step = step
	}
	return m
}

func TestNavigationMax_InitStep3(t *testing.T) {
	m := makeNavModel(INIT, map[int]int{INIT: 3}, 0, 0)
	max, ok := navigationMax(m)
	if !ok || max != 3 {
		t.Errorf("INIT step 3: got (%d, %v), want (3, true)", max, ok)
	}
}

func TestNavigationMax_InitOtherStep(t *testing.T) {
	for _, step := range []int{0, 1, 2, 4} {
		m := makeNavModel(INIT, map[int]int{INIT: step}, 0, 0)
		_, ok := navigationMax(m)
		if ok {
			t.Errorf("INIT step %d: expected (_, false)", step)
		}
	}
}

func TestNavigationMax_ListWithKeyPairs(t *testing.T) {
	m := makeNavModel(LIST, map[int]int{LIST: 0}, 3, 0)
	max, ok := navigationMax(m)
	if !ok || max != 2 {
		t.Errorf("LIST step 0 (3 keys): got (%d, %v), want (2, true)", max, ok)
	}
}

func TestNavigationMax_ListStep2NoNav(t *testing.T) {
	m := makeNavModel(LIST, map[int]int{LIST: 2}, 3, 0)
	_, ok := navigationMax(m)
	if ok {
		t.Error("LIST step 2 should return success=false (filepicker active)")
	}
}

func TestNavigationMax_ListCerts(t *testing.T) {
	m := makeNavModel(LIST_CERTS, nil, 0, 4)
	max, ok := navigationMax(m)
	if !ok || max != 3 {
		t.Errorf("LIST_CERTS (4 certs): got (%d, %v), want (3, true)", max, ok)
	}
}

func TestNavigationMax_ListCertsEmpty(t *testing.T) {
	m := makeNavModel(LIST_CERTS, nil, 0, 0)
	max, ok := navigationMax(m)
	if !ok || max != -1 {
		t.Errorf("LIST_CERTS (0 certs): got (%d, %v), want (-1, true)", max, ok)
	}
}

func TestNavigationMax_SignStep0(t *testing.T) {
	m := makeNavModel(SIGN, map[int]int{SIGN: 0}, 0, 0)
	max, ok := navigationMax(m)
	want := len(signHashOptions) - 1
	if !ok || max != want {
		t.Errorf("SIGN step 0: got (%d, %v), want (%d, true)", max, ok, want)
	}
}

func TestNavigationMax_CreateKeyPairStep1(t *testing.T) {
	m := makeNavModel(CREATE_KEYPAIR, map[int]int{CREATE_KEYPAIR: 1}, 0, 0)
	max, ok := navigationMax(m)
	want := len(keyTypeOptions) - 1
	if !ok || max != want {
		t.Errorf("CREATE_KEYPAIR step 1: got (%d, %v), want (%d, true)", max, ok, want)
	}
}

func TestNavigationMax_CreateKeyPairStep2RSA(t *testing.T) {
	m := makeNavModel(CREATE_KEYPAIR, map[int]int{CREATE_KEYPAIR: 2}, 0, 0)
	m.modes[CREATE_KEYPAIR].KeyType = "RSA"
	max, ok := navigationMax(m)
	want := len(rsaKeyOptions) - 1
	if !ok || max != want {
		t.Errorf("CREATE_KEYPAIR step 2 RSA: got (%d, %v), want (%d, true)", max, ok, want)
	}
}

func TestNavigationMax_CreateKeyPairStep2ECC(t *testing.T) {
	m := makeNavModel(CREATE_KEYPAIR, map[int]int{CREATE_KEYPAIR: 2}, 0, 0)
	m.modes[CREATE_KEYPAIR].KeyType = "ECC"
	max, ok := navigationMax(m)
	want := len(eccKeyOptions) - 1
	if !ok || max != want {
		t.Errorf("CREATE_KEYPAIR step 2 ECC: got (%d, %v), want (%d, true)", max, ok, want)
	}
}

func TestNavigationMax_NoMatch(t *testing.T) {
	m := makeNavModel(IMPORT, nil, 0, 0)
	max, ok := navigationMax(m)
	if ok || max != 0 {
		t.Errorf("IMPORT (no match): got (%d, %v), want (0, false)", max, ok)
	}
}

// ────────────────────────────────────────────────────────────
// exportPublicKey (ctx unused by function — pass nil)
// ────────────────────────────────────────────────────────────

func TestExportPublicKey_RSA(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer := &mockSigner{pub: key.Public()}

	outPath, err := exportPublicKey(nil, signer)
	if err != nil {
		t.Fatalf("exportPublicKey RSA: %v", err)
	}
	if !strings.HasSuffix(outPath, "public.pem") {
		t.Errorf("returned path %q should end with public.pem", outPath)
	}

	content, err := os.ReadFile(filepath.Join(dir, "public.pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(content)
	if block == nil {
		t.Fatal("public.pem contains no PEM block")
	}
	if block.Type != "PUBLIC KEY" {
		t.Errorf("PEM type = %q, want \"PUBLIC KEY\"", block.Type)
	}
	// Round-trip: parse the public key back
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parsing PKIX public key: %v", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", pub)
	}
	if rsaPub.N.Cmp(key.N) != 0 {
		t.Error("exported RSA public key does not match original")
	}
}

func TestExportPublicKey_EC(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := &mockSigner{pub: key.Public()}

	_, err = exportPublicKey(nil, signer)
	if err != nil {
		t.Fatalf("exportPublicKey EC: %v", err)
	}

	content, err := os.ReadFile(filepath.Join(dir, "public.pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(content)
	if block == nil || block.Type != "PUBLIC KEY" {
		t.Errorf("expected PUBLIC KEY PEM block")
	}
}

// ────────────────────────────────────────────────────────────
// signFiles
// ────────────────────────────────────────────────────────────

func TestSignFiles_CreatesSignaturePEM(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	dataFile := filepath.Join(dir, "data.txt")
	if err := os.WriteFile(dataFile, []byte("hello world"), 0644); err != nil {
		t.Fatal(err)
	}

	signer := &mockSigner{sig: []byte("fake-sig-bytes")}
	outPath, err := signFiles(signer, []string{dataFile}, crypto.SHA256)
	if err != nil {
		t.Fatalf("signFiles: %v", err)
	}
	if !strings.HasSuffix(outPath, "signature.pem") {
		t.Errorf("returned path %q should end with signature.pem", outPath)
	}

	content, err := os.ReadFile(filepath.Join(dir, "signature.pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(content)
	if block == nil {
		t.Fatal("signature.pem contains no PEM block")
	}
	if block.Type != "SIGNATURE" {
		t.Errorf("PEM type = %q, want \"SIGNATURE\"", block.Type)
	}
	if string(block.Bytes) != "fake-sig-bytes" {
		t.Errorf("signature bytes = %q, want %q", block.Bytes, "fake-sig-bytes")
	}
}

func TestSignFiles_MultipleFiles(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	f1 := filepath.Join(dir, "a.txt")
	f2 := filepath.Join(dir, "b.txt")
	os.WriteFile(f1, []byte("aaa"), 0644)
	os.WriteFile(f2, []byte("bbb"), 0644)

	signer := &mockSigner{sig: []byte{0x01, 0x02, 0x03}}
	_, err := signFiles(signer, []string{f1, f2}, crypto.SHA512)
	if err != nil {
		t.Fatalf("signFiles (multiple files): %v", err)
	}
}

func TestSignFiles_UnsupportedHash(t *testing.T) {
	signer := &mockSigner{}
	_, err := signFiles(signer, []string{}, crypto.MD5)
	if err == nil {
		t.Error("expected error for unsupported hash algorithm")
	}
}

func TestSignFiles_SignerError(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	dataFile := filepath.Join(dir, "data.txt")
	os.WriteFile(dataFile, []byte("test data"), 0644)

	signer := &mockSigner{err: errors.New("HSM sign error")}
	_, err := signFiles(signer, []string{dataFile}, crypto.SHA256)
	if err == nil {
		t.Error("expected error when signer.Sign fails")
	}
}

func TestSignFiles_MissingInputFile(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	signer := &mockSigner{sig: []byte("sig")}
	_, err := signFiles(signer, []string{"/nonexistent/file.txt"}, crypto.SHA256)
	if err == nil {
		t.Error("expected error for missing input file")
	}
}

// ────────────────────────────────────────────────────────────
// LoadX509KeyPair
// ────────────────────────────────────────────────────────────

func writeCertAndKey(t *testing.T, dir string, certDER, keyPEM []byte, keyType string) (certFile, keyFile string) {
	t.Helper()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")

	cf, err := os.Create(certFile)
	if err != nil {
		t.Fatal(err)
	}
	pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	cf.Close()

	kf, err := os.Create(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	pem.Encode(kf, &pem.Block{Type: keyType, Bytes: keyPEM})
	kf.Close()
	return
}

func selfSignedTemplate(serial int64) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
}

func TestLoadX509KeyPair_PKCS1RSA(t *testing.T) {
	dir := t.TempDir()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := selfSignedTemplate(1)
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	certFile, keyFile := writeCertAndKey(t, dir, certDER, x509.MarshalPKCS1PrivateKey(key), "RSA PRIVATE KEY")

	cert, gotKey, err := LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("LoadX509KeyPair PKCS1 RSA: %v", err)
	}
	if cert == nil {
		t.Error("cert is nil")
	}
	if gotKey == nil {
		t.Error("key is nil")
	}
	if _, ok := gotKey.(*rsa.PrivateKey); !ok {
		t.Errorf("expected *rsa.PrivateKey, got %T", gotKey)
	}
}

func TestLoadX509KeyPair_PKCS8RSA(t *testing.T) {
	dir := t.TempDir()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := selfSignedTemplate(2)
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	certFile, keyFile := writeCertAndKey(t, dir, certDER, pkcs8DER, "PRIVATE KEY")

	cert, gotKey, err := LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("LoadX509KeyPair PKCS8 RSA: %v", err)
	}
	if cert == nil || gotKey == nil {
		t.Error("cert or key is nil")
	}
}

func TestLoadX509KeyPair_EC(t *testing.T) {
	dir := t.TempDir()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := selfSignedTemplate(3)
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	certFile, keyFile := writeCertAndKey(t, dir, certDER, ecDER, "EC PRIVATE KEY")

	cert, gotKey, err := LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("LoadX509KeyPair EC: %v", err)
	}
	if cert == nil || gotKey == nil {
		t.Error("cert or key is nil")
	}
	if _, ok := gotKey.(*ecdsa.PrivateKey); !ok {
		t.Errorf("expected *ecdsa.PrivateKey, got %T", gotKey)
	}
}

func TestLoadX509KeyPair_MissingCertFile(t *testing.T) {
	_, _, err := LoadX509KeyPair("/nonexistent/cert.pem", "/nonexistent/key.pem")
	if err == nil {
		t.Error("expected error for missing cert file")
	}
}

func TestLoadX509KeyPair_MissingKeyFile(t *testing.T) {
	dir := t.TempDir()

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := selfSignedTemplate(4)
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	certFile, _ := writeCertAndKey(t, dir, certDER, []byte{}, "RSA PRIVATE KEY")

	_, _, err := LoadX509KeyPair(certFile, "/nonexistent/key.pem")
	if err == nil {
		t.Error("expected error for missing key file")
	}
}

func TestLoadX509KeyPair_UnparseableKey(t *testing.T) {
	dir := t.TempDir()

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := selfSignedTemplate(5)
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)

	// Write valid cert but garbage key bytes
	certFile, keyFile := writeCertAndKey(t, dir, certDER, []byte("not-a-key"), "PRIVATE KEY")

	_, _, err := LoadX509KeyPair(certFile, keyFile)
	if err == nil {
		t.Error("expected error for unparseable key")
	}
}
