package main

import (
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
	CREATE_KEYPAIR = 3
)

type Mode struct {
	ModeNumber  int
	Name        string
	Handler     func(msg tea.Msg, m model) (model, tea.Cmd)
	ViewHandler func(m model) tea.View
	Step        int
	// temporary storage for IMPORT
	CertPath       string
	PrivateKeyPath string
	PublicKeyPath  string
}

var modes []Mode

func init() {
	modes = []Mode{
		{ModeNumber: INIT, Name: "Initial Mode", Handler: handleInit, ViewHandler: HandleViewInit, Step: 0},
		{ModeNumber: IMPORT, Name: "import a TLS-Certificate and Keypair into my HSM", Handler: handleImport, ViewHandler: HandleViewImport, Step: 0},
		{ModeNumber: LIST, Name: "List all Keypairs", Handler: handleList, ViewHandler: HandleViewList, Step: 0},
		{ModeNumber: CREATE_KEYPAIR, Name: "create a key pair", Handler: handleKeyPair, ViewHandler: HandleViewKeyPair, Step: 0},
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
	ctx           *crypto11.Context

	termHeight int

	textInput  textinput.Model
	filepicker filepicker.Model
}

func (m model) Init() tea.Cmd {
	return nil
}

func initialModel() model {
	return model{
		cursor:        0,
		modes:         modes,
		selectedMode:  INIT,
		textInput:     initializeTextInput(),
		debuggingMode: true,
	}
}

func initializeTextInput() textinput.Model {
	ti := textinput.New()
	ti.Placeholder = "i.e. /usr/lib/pkcs11/opensc.so"
	ti.SetVirtualCursor(false)
	ti.Focus()
	ti.CharLimit = 156
	ti.SetWidth(20)
	return ti
}
