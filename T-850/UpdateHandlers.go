package main

import (
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

func handleInit(msg tea.Msg, m model) (model, tea.Cmd) {
	//TODO: make case for one-file-keypairs
	switch m.modes[INIT].Step {
	case -1:
		time.Sleep(3 * time.Second)
		m.modes[INIT].Step = 0
		return m, nil

	case 0:
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
					m.exitMessage = err.Error()
					m.FinishError = true
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
				m.filepicker = newFilepicker(m, []string{".pem", ".crt", ".cer", ".der"})
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
		m.exitMessage = fmt.Sprintf("Successfully imported certificate: %s", cp)
		return m, nil

	}
	return m, nil
}

func handleKeyPair(msg tea.Msg, m model) (model, tea.Cmd) {
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
			msg, err := importCertForKeyPair(m.ctx, m.modes[LIST].selectedKP, path)
			if err != nil {
				m.exitMessage = err.Error()
				m.FinishError = true
				return m, nil
			}
			m.exitMessage = msg
			return m, nil
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
