package main

import (
	"fmt"
	"os"

	"charm.land/bubbles/v2/filepicker"
	"charm.land/bubbles/v2/textinput"
	_ "charm.land/bubbletea/v2"
	tea "charm.land/bubbletea/v2"
	"github.com/miekg/pkcs11"
)

type pkcs11config struct {
	TokenLabel string
	KeyAlias   string
	KeyID      string
	SoPIN      string
	Pin        string
	DriverPath string
}

type PKCS11Object struct {
	Object  string
	Bits    string
	Label   string
	Subject string
	Serial  string
	Usage   string
	Access  string
	URI     string
}

type token struct {
	slotName      string
	alias         string
	pkcs11Objects []PKCS11Object
}

type TokenInfo struct {
	Label              string
	ManufacturerID     string
	Model              string
	SerialNumber       string
	Flags              uint
	MaxSessionCount    string // "unavailable" or count
	SessionCount       string
	MaxRwSessionCount  string
	RwSessionCount     string
	MinPinLen          uint
	MaxPinLen          uint
	TotalPublicMemory  string
	FreePublicMemory   string
	TotalPrivateMemory string
	FreePrivateMemory  string
	HardwareVersion    string // "Major.Minor"
	FirmwareVersion    string
}

func (k *TokenInfo) String() string {
	s := fmt.Sprintf("label: %s", k.Label)
	return s
}

type Key struct {
	id      string
	label   string
	keyType string
}

func (k *Key) String() string {
	s := fmt.Sprintf("Key: id: %s,label: %s, keyType %s", k.id, k.label, k.keyType)
	return s
}

type model struct {
	mode          mode
	cursor        int
	tokens        []TokenInfo
	selectedToken TokenInfo
	textInput     textinput.Model //reused to fetch text i.e. for encryption or filling of information in
	filepicker    filepicker.Model
	selectedPath  string
	pkcs11config  pkcs11config
	keys          []Key
}

func (m model) Init() tea.Cmd {
	m.filepicker.Init()
	return nil
}
func initialModel() model {
	return model{
		mode:       modes[0],
		cursor:     0,
		textInput:  initializeTextInput(),
		filepicker: initializeFilePicker(),
	}

}

func initializeTextInput() textinput.Model {
	ti := textinput.New()
	ti.Placeholder = "Pikachu"
	ti.SetVirtualCursor(false)
	ti.Focus()
	ti.CharLimit = 156
	ti.SetWidth(20)
	return ti
}

func initializeFilePicker() filepicker.Model {
	fp := filepicker.New()
	fp.AllowedTypes = []string{".toml", ".TOML"}
	fp.CurrentDirectory, _ = os.Getwd()
	return fp

}

var ckkNames = map[uint64]string{
	pkcs11.CKK_RSA:            "RSA",
	pkcs11.CKK_DSA:            "DSA",
	pkcs11.CKK_DH:             "DH",
	pkcs11.CKK_EC:             "EC (ECC)", // CKK_ECDSA is deprecated alias for same value
	pkcs11.CKK_X9_42_DH:       "X9_42_DH",
	pkcs11.CKK_KEA:            "KEA",
	pkcs11.CKK_GENERIC_SECRET: "GENERIC_SECRET",
	pkcs11.CKK_RC2:            "RC2",
	pkcs11.CKK_RC4:            "RC4",
	pkcs11.CKK_DES:            "DES",
	pkcs11.CKK_DES2:           "DES2",
	pkcs11.CKK_DES3:           "DES3",
	pkcs11.CKK_CAST:           "CAST",
	pkcs11.CKK_CAST3:          "CAST3",
	pkcs11.CKK_CAST128:        "CAST128", // CKK_CAST5 is deprecated alias
	pkcs11.CKK_RC5:            "RC5",
	pkcs11.CKK_IDEA:           "IDEA",
	pkcs11.CKK_SKIPJACK:       "SKIPJACK",
	pkcs11.CKK_BATON:          "BATON",
	pkcs11.CKK_JUNIPER:        "JUNIPER",
	pkcs11.CKK_CDMF:           "CDMF",
	pkcs11.CKK_AES:            "AES",
	pkcs11.CKK_BLOWFISH:       "BLOWFISH",
	pkcs11.CKK_TWOFISH:        "TWOFISH",
	pkcs11.CKK_SECURID:        "SECURID",
	pkcs11.CKK_HOTP:           "HOTP",
	pkcs11.CKK_ACTI:           "ACTI",
	pkcs11.CKK_CAMELLIA:       "CAMELLIA",
	pkcs11.CKK_ARIA:           "ARIA",
	pkcs11.CKK_MD5_HMAC:       "MD5_HMAC",
	pkcs11.CKK_SHA_1_HMAC:     "SHA1_HMAC",
	pkcs11.CKK_RIPEMD128_HMAC: "RIPEMD128_HMAC",
	pkcs11.CKK_RIPEMD160_HMAC: "RIPEMD160_HMAC",
	pkcs11.CKK_SHA256_HMAC:    "SHA256_HMAC",
	pkcs11.CKK_SHA384_HMAC:    "SHA384_HMAC",
	pkcs11.CKK_SHA512_HMAC:    "SHA512_HMAC",
	pkcs11.CKK_SHA224_HMAC:    "SHA224_HMAC",
	pkcs11.CKK_SEED:           "SEED",
	pkcs11.CKK_GOSTR3410:      "GOSTR3410",
	pkcs11.CKK_GOSTR3411:      "GOSTR3411",
	pkcs11.CKK_GOST28147:      "GOST28147",
	pkcs11.CKK_VENDOR_DEFINED: "VENDOR_DEFINED",
}
