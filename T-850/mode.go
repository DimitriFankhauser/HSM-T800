package main

import (
	"crypto"
	"crypto/tls"

	"charm.land/bubbles/v2/filepicker"
	"charm.land/bubbles/v2/textinput"
	_ "charm.land/bubbletea/v2"
	tea "charm.land/bubbletea/v2"
	"github.com/ThalesGroup/crypto11"
)

const (
	INIT           = 0
	IMPORT         = 1
	LIST           = 2
	LIST_CERTS     = 3
	CREATE_KEYPAIR = 4
	SIGN           = 5
)

type Mode struct {
	ModeNumber  int
	Name        string
	Handler     func(msg tea.Msg, m model) (model, tea.Cmd)
	ViewHandler func(m model) tea.View
	Step        int

	// IMPORT
	CertPath       string
	PrivateKeyPath string
	PublicKeyPath  string

	// LIST Mode
	selectedKP crypto11.Signer

	// LIST_CERT
	selectedCert tls.Certificate

	// CREATE_KEYPAIR
	KeyLabel string
	KeyType  string
	KeyBits  int

	// SIGN
	SignFiles  []string
	SigningKey crypto11.Signer
	HashAlgo   crypto.Hash
}

var modes []Mode

func init() {
	modes = []Mode{
		{ModeNumber: INIT, Name: "Initial Mode", Handler: handleInit, ViewHandler: HandleViewInit, Step: -1},
		{ModeNumber: IMPORT, Name: "import a TLS-Certificate and Keypair into my HSM", Handler: handleImport, ViewHandler: HandleViewImport, Step: 0},
		{ModeNumber: LIST, Name: "List all Keypairs", Handler: handleList, ViewHandler: HandleViewList, Step: 0},
		{ModeNumber: LIST_CERTS, Name: "List all Certificates", Handler: handleListCerts, ViewHandler: HandleViewListCerts, Step: 0},
		{ModeNumber: CREATE_KEYPAIR, Name: "create a key", Handler: handleKeyPair, ViewHandler: HandleViewKeyPair, Step: 0},
		{ModeNumber: SIGN, Name: "sign files with a key pair", Handler: handleSign, ViewHandler: HandleViewSign, Step: 0},
	}
}

type model struct {
	cursor        int
	selectedMode  int
	modes         []Mode
	pathToSo      string
	tokenLabel    string
	pin           string
	keyLabel      string
	debuggingMode bool
	errorMsg      string
	keyPairs      []crypto11.Signer
	certificates  []tls.Certificate
	ctx           *crypto11.Context

	termHeight int

	// finish error is set, when an error happens
	FinishError bool

	exitMessage string
	statusMsg   string // shown on the main menu after a successful mutating operation

	textInput  textinput.Model
	filepicker filepicker.Model
}

func (m model) Init() tea.Cmd {
	return nil
}

func initialModel(debug bool, modulePath, tokenLabel, pin string) model {
	m := model{
		cursor:        0,
		modes:         modes,
		selectedMode:  INIT,
		textInput:     initializeTextInput(),
		debuggingMode: debug,
		FinishError:   false,
		exitMessage:   "",
	}
	if modulePath != "" {
		m.pathToSo = modulePath
	}
	if tokenLabel != "" {
		m.tokenLabel = tokenLabel
	}
	if pin != "" {
		m.pin = pin
	}
	return m
}

func initializeTextInput() textinput.Model {
	ti := textinput.New()
	ti.Placeholder = "i.e. /usr/lib/pkcs11/opensc.so"
	ti.SetVirtualCursor(false)
	ti.Focus()
	ti.CharLimit = 156
	ti.SetWidth(40)
	return ti
}
