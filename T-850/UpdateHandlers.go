package main

import (
	"crypto/rand"
	"os"
	"unicode"

	"charm.land/bubbles/v2/filepicker"
	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
)

const DEBUG_PATHTOSO = "/usr/lib64/softhsm/libsofthsm.so"
const DEBUG_TOKENLABEL = "Genesis"
const DEBUG_PIN = "123456789"

func handleInit(msg tea.Msg, m model) (model, tea.Cmd) {
	switch m.modes[INIT].Step {
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
				initializeCtx(&m)
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
					m.keyPairs = getKeyPairs(m.ctx)
					m.selectedMode = LIST
				case 2:
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
		_, key := LoadX509KeyPair(m.modes[IMPORT].CertPath, m.modes[IMPORT].PrivateKeyPath)

		id := make([]byte, 16)
		rand.Read(id)

		if err := importKeyPair(m.pathToSo, m.tokenLabel, m.pin, key, id, m.keyLabel); err != nil {
			m.errorMsg = err.Error()
		}
		return m, tea.Quit

	}
	return m, nil
}

func handleKeyPair(msg tea.Msg, m model) (model, tea.Cmd) {
	return m, nil
}

func handleList(msg tea.Msg, m model) (model, tea.Cmd) {
	return m, tea.Quit
}
