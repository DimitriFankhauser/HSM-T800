package main

import (
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
				case 1:
					initializeCtx(&m)
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

func handleImport(msg tea.Msg, m model) (model, tea.Cmd) {
	return m, nil
}

func handleKeyPair(msg tea.Msg, m model) (model, tea.Cmd) {
	return m, nil
}

func handleList(msg tea.Msg, m model) (model, tea.Cmd) {
	return m, tea.Quit
}
