package main

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"os"
	"time"
	"unicode"

	"charm.land/bubbles/v2/filepicker"
	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
)

const DEBUG_PATHTOSO = "/usr/lib64/softhsm/libsofthsm.so"
const DEBUG_TOKENLABEL = "Genesis"
const DEBUG_PIN = "123456789"

// prefilledMsg is sent as a command to immediately trigger the next Update
// cycle when init steps are auto-advanced from CLI flags.
type prefilledMsg struct{}

func prefilledCmd() tea.Cmd {
	return func() tea.Msg { return prefilledMsg{} }
}

func handleInit(msg tea.Msg, m model) (model, tea.Cmd) {
	//TODO: make case for one-file-keypairs
	switch m.modes[INIT].Step {
	case -1:
		time.Sleep(3 * time.Second)
		m.modes[INIT].Step = 0
		// Send a message so that step 0 is processed right away when flags
		// have already pre-filled the connection parameters.
		return m, prefilledCmd()

	case 0:
		// Auto-advance when --modulePath was supplied on the command line.
		if m.pathToSo != "" {
			if !checkFileExists(m.pathToSo) {
				m.exitMessage = "Invalid --modulePath: file not found: " + m.pathToSo
				m.FinishError = true
				return m, nil
			}
			m.textInput.Reset()
			m.textInput.Placeholder = "Enter Token Label"
			m.modes[INIT].Step = 1
			return m, prefilledCmd()
		}
		switch msg := msg.(type) {
		case tea.KeyMsg:
			if msg.String() == "enter" {
				if m.debuggingMode {
					m.pathToSo = DEBUG_PATHTOSO
				} else {
					m.pathToSo = m.textInput.Value()
				}
				if !checkFileExists(m.pathToSo) {
					m.errorMsg = "File not found: " + m.pathToSo
					m.pathToSo = ""
					m.textInput.Reset()
					return m, nil
				}
				m.errorMsg = ""
				m.textInput.Reset()
				m.textInput.Placeholder = "Enter Token Label"
				m.modes[INIT].Step = 1
				return m, nil
			}
		}
		var cmd tea.Cmd
		m.textInput, cmd = m.textInput.Update(msg)
		return m, cmd

	case 1:
		// Auto-advance when --label was supplied on the command line.
		if m.tokenLabel != "" {
			if !checkTokenExists(m.pathToSo, m.tokenLabel) {
				m.exitMessage = fmt.Sprintf("Invalid --label: token '%s' couldn't be found", m.tokenLabel)
				m.FinishError = true
				return m, nil
			}
			m.textInput.Reset()
			m.textInput.Placeholder = "Enter PIN"
			m.textInput.EchoMode = textinput.EchoPassword
			m.modes[INIT].Step = 2
			return m, prefilledCmd()
		}
		switch msg := msg.(type) {
		case tea.KeyMsg:
			if msg.String() == "enter" {
				var tokenLabel string
				if m.debuggingMode {
					tokenLabel = DEBUG_TOKENLABEL
				} else {
					tokenLabel = m.textInput.Value()
				}
				if len(tokenLabel) == 0 {
					m.errorMsg = "Token label cannot be empty"
					m.textInput.Reset()
					return m, nil
				}
				if !checkTokenExists(m.pathToSo, tokenLabel) {
					m.errorMsg = fmt.Sprintf("Token '%s' couldn't be found", tokenLabel)
					m.textInput.Reset()
					return m, nil
				}
				m.tokenLabel = tokenLabel
				m.errorMsg = ""
				m.textInput.Reset()
				m.textInput.Placeholder = "Enter PIN"
				m.textInput.EchoMode = textinput.EchoPassword
				m.modes[INIT].Step = 2
				return m, nil
			}
		}
		var cmd tea.Cmd
		m.textInput, cmd = m.textInput.Update(msg)
		return m, cmd

	case 2:
		// Auto-advance when --pin was supplied on the command line.
		if m.pin != "" {
			if len(m.pin) < 4 {
				m.exitMessage = "Invalid --pin: must be at least 4 characters"
				m.FinishError = true
				return m, nil
			}
			if err := initializeCtx(&m); err != nil {
				m.exitMessage = err.Error()
				m.FinishError = true
				return m, nil
			}
			m.textInput.Reset()
			m.modes[INIT].Step = 3
			return m, nil
		}
		switch msg := msg.(type) {
		case tea.KeyMsg:
			if msg.String() == "enter" {
				var pin string
				if m.debuggingMode {
					pin = DEBUG_PIN
				} else {
					pin = m.textInput.Value()
				}
				if len(pin) < 4 {
					m.errorMsg = "PIN must be at least 4 characters"
					m.textInput.Reset()
					return m, nil
				}
				m.pin = pin
				if err := initializeCtx(&m); err != nil {
					m.errorMsg = err.Error()
					m.pin = ""
					m.textInput.Reset()
					return m, nil
				}
				m.errorMsg = ""
				m.textInput.Reset()
				m.modes[INIT].Step = 3
				return m, nil
			}
		}
		var cmd tea.Cmd
		m.textInput, cmd = m.textInput.Update(msg)
		return m, cmd

	case 3:
		switch msg := msg.(type) {
		case tea.KeyMsg:
			if msg.String() == "enter" {
				m.statusMsg = ""
				switch m.cursor {
				case 0:
					m.selectedMode = IMPORT
					m.textInput.Reset()
					m.textInput.Placeholder = "Enter Key Label"
					m.textInput.EchoMode = textinput.EchoNormal
				case 1:
					m.cursor = 0
					kps, err := getKeyPairs(m.ctx)
					if err != nil {
						m.exitMessage = err.Error()
						m.FinishError = true
						return m, nil
					}
					m.keyPairs = kps
					m.selectedMode = LIST
				case 2:
					m.cursor = 0
					certs, err := getCertificates(m.ctx)
					if err != nil {
						m.exitMessage = err.Error()
						m.FinishError = true
						return m, nil
					}
					m.certificates = certs
					m.selectedMode = LIST_CERTS
				case 3:
					ck := m.modes[CREATE_KEYPAIR]
					ck.Step = 0
					m.modes[CREATE_KEYPAIR] = ck
					m.cursor = 0
					m.textInput.Reset()
					m.textInput.Placeholder = "Enter key label"
					m.textInput.EchoMode = textinput.EchoNormal
					m.selectedMode = CREATE_KEYPAIR
				}
				m.modes[INIT].Step = 4
			}
		}
	}
	return m, nil
}

func isValidLabel(s string) bool {
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' && r != '-' {
			return false
		}
	}
	return true
}

func newFilepicker(m model, allowedTypes []string) filepicker.Model {
	fp := filepicker.New()
	fp.AllowedTypes = allowedTypes
	if cwd, err := os.Getwd(); err == nil {
		fp.CurrentDirectory = cwd
	}
	if m.termHeight > 0 {
		fp.SetHeight(m.termHeight - 5)
	}
	return fp
}

func handleImport(msg tea.Msg, m model) (model, tea.Cmd) {
	switch m.modes[IMPORT].Step {
	case 0:
		switch msg := msg.(type) {
		case tea.KeyMsg:
			if msg.String() == "enter" {
				keyLabel := m.textInput.Value()
				if len(keyLabel) == 0 {
					m.errorMsg = "Key label cannot be empty"
					m.textInput.Reset()
					return m, nil
				}
				if !isValidLabel(keyLabel) {
					m.errorMsg = "Key label must only contain letters, digits, - or _"
					m.textInput.Reset()
					return m, nil
				}
				m.keyLabel = keyLabel
				m.errorMsg = ""
				m.filepicker = newFilepicker(m, []string{".pem", ".crt", ".cer"})
				m.textInput.Reset()
				m.modes[IMPORT].Step = 1
				return m, m.filepicker.Init()
			}
		}
		var cmd tea.Cmd
		m.textInput, cmd = m.textInput.Update(msg)
		return m, cmd

	case 1:
		var cmd tea.Cmd
		m.filepicker, cmd = m.filepicker.Update(msg)
		if selected, path := m.filepicker.DidSelectFile(msg); selected {
			m.modes[IMPORT].CertPath = path
			m.filepicker = newFilepicker(m, []string{".pem", ".key", ".pub"})
			m.modes[IMPORT].Step = 2
			return m, m.filepicker.Init()
		}
		return m, cmd

	case 2:
		var cmd tea.Cmd
		m.filepicker, cmd = m.filepicker.Update(msg)
		if selected, path := m.filepicker.DidSelectFile(msg); selected {
			m.modes[IMPORT].PrivateKeyPath = path
			m.filepicker = newFilepicker(m, []string{".pem", ".key", ".pub"})
			m.modes[IMPORT].Step = 3
			return m, m.filepicker.Init()
		}
		return m, cmd

	case 3:
		var cmd tea.Cmd
		m.filepicker, cmd = m.filepicker.Update(msg)
		if selected, path := m.filepicker.DidSelectFile(msg); selected {
			m.modes[IMPORT].PublicKeyPath = path
			m.modes[IMPORT].Step = 4
			return m, nil
		}
		return m, cmd

	case 4:
		_, key, err := LoadX509KeyPair(m.modes[IMPORT].CertPath, m.modes[IMPORT].PrivateKeyPath)
		if err != nil {
			m.exitMessage = err.Error()
			m.FinishError = true
			return m, nil
		}

		id := make([]byte, 16)
		rand.Read(id)

		if err := importKeyPair(m.pathToSo, m.tokenLabel, m.pin, key, id, m.keyLabel); err != nil {
			m.exitMessage = err.Error()
			m.FinishError = true
			return m, nil
		}
		cp, err := ImportCert(m.ctx, id, m.modes[IMPORT].CertPath)
		if err != nil {
			m.exitMessage = err.Error()
			m.FinishError = true
			return m, nil
		}
		return returnToMenu(m, fmt.Sprintf("Successfully imported certificate: %s", cp)), nil

	}
	return m, nil
}

var keyTypeOptions = []string{"RSA", "ECC"}

var rsaKeyOptions = []struct {
	label string
	bits  int
}{
	{"2048 bit", 2048},
	{"3072 bit", 3072},
	{"4096 bit", 4096},
}

var eccKeyOptions = []struct {
	label string
	curve elliptic.Curve
}{
	{"P-256", elliptic.P256()},
	{"P-384", elliptic.P384()},
	{"P-521", elliptic.P521()},
}

func handleKeyPair(msg tea.Msg, m model) (model, tea.Cmd) {
	ck := m.modes[CREATE_KEYPAIR]
	switch ck.Step {
	case 0:
		if key, ok := msg.(tea.KeyMsg); ok && key.String() == "enter" {
			label := m.textInput.Value()
			if len(label) == 0 {
				m.errorMsg = "Key label cannot be empty"
				m.textInput.Reset()
				return m, nil
			}
			if !isValidLabel(label) {
				m.errorMsg = "Key label must only contain letters, digits, - or _"
				m.textInput.Reset()
				return m, nil
			}
			ck.KeyLabel = label
			m.errorMsg = ""
			m.textInput.Reset()
			ck.Step = 1
			m.modes[CREATE_KEYPAIR] = ck
			m.cursor = 0
			return m, nil
		}
		var cmd tea.Cmd
		m.textInput, cmd = m.textInput.Update(msg)
		return m, cmd

	case 1:
		if key, ok := msg.(tea.KeyMsg); ok && key.String() == "enter" {
			ck.KeyType = keyTypeOptions[m.cursor]
			ck.Step = 2
			m.modes[CREATE_KEYPAIR] = ck
			m.cursor = 0
		}
		return m, nil

	case 2:
		if key, ok := msg.(tea.KeyMsg); ok {
			switch key.String() {
			case "enter":
				if ck.KeyType == "RSA" {
					opt := rsaKeyOptions[m.cursor]
					ck.KeyBits = opt.bits
					m.modes[CREATE_KEYPAIR] = ck
					if err := createRSAKeyPair(m.ctx, ck.KeyLabel, ck.KeyBits); err != nil {
						m.exitMessage = err.Error()
						m.FinishError = true
						return m, nil
					}
					return returnToMenu(m, fmt.Sprintf("RSA-Key (%d-bits) with label '%s' was created", ck.KeyBits, ck.KeyLabel)), nil
				} else {
					opt := eccKeyOptions[m.cursor]
					m.modes[CREATE_KEYPAIR] = ck
					if err := createECCKeyPair(m.ctx, ck.KeyLabel, opt.curve); err != nil {
						m.exitMessage = err.Error()
						m.FinishError = true
						return m, nil
					}
					return returnToMenu(m, fmt.Sprintf("ECC-Key (%s) with label '%s' was created", opt.label, ck.KeyLabel)), nil
				}
			}
		}
		return m, nil
	}
	return m, nil
}

var signHashOptions = []struct {
	label string
	algo  crypto.Hash
}{
	{"SHA-256", crypto.SHA256},
	{"SHA-384", crypto.SHA384},
	{"SHA-512", crypto.SHA512},
}

func handleSign(msg tea.Msg, m model) (model, tea.Cmd) {
	switch m.modes[SIGN].Step {
	case 0:
		if key, ok := msg.(tea.KeyMsg); ok && key.String() == "enter" {
			sign := m.modes[SIGN]
			sign.HashAlgo = signHashOptions[m.cursor].algo
			sign.Step = 1
			m.modes[SIGN] = sign
			m.cursor = 0
			m.filepicker = newFilepicker(m, []string{})
			return m, m.filepicker.Init()
		}
		return m, nil

	case 1:
		if key, ok := msg.(tea.KeyMsg); ok && key.String() == "tab" {
			if len(m.modes[SIGN].SignFiles) == 0 {
				m.errorMsg = "Select at least one file before signing"
				return m, nil
			}
			outPath, err := signFiles(m.modes[SIGN].SigningKey, m.modes[SIGN].SignFiles, m.modes[SIGN].HashAlgo)
			if err != nil {
				m.exitMessage = err.Error()
				m.FinishError = true
				return m, nil
			}
			m.exitMessage = fmt.Sprintf("Signature written to %s", outPath)
			m.FinishError = false
			return m, nil
		}
		var cmd tea.Cmd
		m.filepicker, cmd = m.filepicker.Update(msg)
		if selected, path := m.filepicker.DidSelectFile(msg); selected {
			sign := m.modes[SIGN]
			sign.SignFiles = append(sign.SignFiles, path)
			m.modes[SIGN] = sign
			m.filepicker = newFilepicker(m, []string{})
			return m, m.filepicker.Init()
		}
		return m, cmd
	}
	return m, nil
}

func handleList(msg tea.Msg, m model) (model, tea.Cmd) {
	switch m.modes[LIST].Step {
	case 0:
		m.modes[LIST].selectedKP = m.keyPairs[m.cursor]
		m.modes[LIST].Step = 1
		return m, nil
	case 2:
		var cmd tea.Cmd
		m.filepicker, cmd = m.filepicker.Update(msg)
		if selected, path := m.filepicker.DidSelectFile(msg); selected {
			notice, err := importCertForKeyPair(m.ctx, m.modes[LIST].selectedKP, path)
			if err != nil {
				m.exitMessage = err.Error()
				m.FinishError = true
				return m, nil
			}
			m.modes[LIST].Step = 0
			m.modes[LIST].selectedKP = nil
			return returnToMenu(m, notice), nil
		}
		return m, cmd
	}
	return m, nil
}
func handleListCerts(msg tea.Msg, m model) (model, tea.Cmd) {
	m.modes[LIST_CERTS].Step++
	m.modes[LIST_CERTS].selectedCert = m.certificates[m.cursor]
	return m, nil
}
