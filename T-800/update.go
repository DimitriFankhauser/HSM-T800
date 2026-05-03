package main

import (
	tea "charm.land/bubbletea/v2"
)

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+q":
			return m, tea.Quit

		case "up":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down":
			if m.cursor < len(m.mode.options)-1 {
				m.cursor++
			}
		case "enter":
			if m.mode.modeNum == READ_CONFIG_FILE || m.mode.modeNum == GET_ENCRYPTABLE_FILE {
				break
			}
			return handleEnter(m, msg)
		}
	}

	var textCmd, pickerCmd tea.Cmd
	m.textInput, textCmd = m.textInput.Update(msg)
	m.filepicker, pickerCmd = m.filepicker.Update(msg)

	switch m.mode.modeNum {
	case READ_CONFIG_FILE:
		if didSelect, path := m.filepicker.DidSelectFile(msg); didSelect {
			m.selectedPath = path
			m.mode = modes[CONFIRM_SELECTED_CONFIG]
			return m, tea.Batch(textCmd, pickerCmd)
		}
	case GET_ENCRYPTABLE_FILE:
		if didSelect, path := m.filepicker.DidSelectFile(msg); didSelect {
			m.selectedPath = path
			m.mode = modes[ENCRYPTION_OPERATION_DONE]
			return m, tea.Batch(textCmd, pickerCmd)
		}
	}

	return m, tea.Batch(textCmd, pickerCmd)
}

var configAttributes = []string{}

func handleEnter(m model, msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch m.mode.modeNum {
	case STARTMODE:
		switch m.cursor {
		case 0:
			//cursor will be reused as index to loop through options
			m.cursor = 0
			m.mode = modes[READ_CONFIG_USER]
			return m, nil
		case 1:
			m.cursor = 0
			m.mode = modes[READ_CONFIG_FILE]
			return m, nil
		}
	case READ_CONFIG_USER:
		conigAttribute := m.textInput.Value()
		configAttributes = append(configAttributes, conigAttribute)
		m.textInput.Reset()
		if m.cursor < len(m.mode.options)-1 {
			m.cursor++
			return m, nil
		}
		m.cursor = 0
		m.mode = modes[CONFIRM_SELECTED_CONFIG]
		return m, nil
	case READ_CONFIG_FILE:
		return m, nil
	case CONFIRM_SELECTED_CONFIG:
		switch m.cursor {
		case 0:
			m.mode = modes[CONFIG_CONFIRMED]
			return assignConfigObject(m)
			//TODO: assign internal CONFIG-Object. Clean up FP-Input for later use
		case 1:
			return m, tea.Quit
		}
	case CONFIG_CONFIRMED:
		switch m.cursor {
		case 0:
			return UpdateTokens(m)
		case 1:
			m.mode = modes[CREATE_TOKEN]
			return m, tea.Quit
		}
	case CREATE_TOKEN:
		//TODO: create a token based on config.
		// then call UpdateTokens(m) to deliver a fresh list of all the tokens there
		// then let users (via VIEW) select a token and move to SELECT_TOKEN
		return m, nil
	case SELECT_TOKEN:
		//TODO: recover user's choice, move to next step and operate on that token
		m.selectedToken = m.tokens[m.cursor]
		m.mode = modes[OPERATE_ON_TOKEN]
		m.cursor = 0
		return m, nil

	case OPERATE_ON_TOKEN:
		switch m.cursor {
		case 0:
			return m, nil

		case 1:
			// Select Asymmetric Keys
			return UpdateAsymmetricKeys(m)
		case 2:
			// Select Symmetric Keys
			return UpdateSymmetricKeys(m)
		case 3:
			// Select a certificate
			return UpdateCertificates(m)
			return m, nil
		case 4:
			// use HSM for Keyless work (i.e. Sha256 Digest)
			return m, nil

		}

	}
	return m, nil
}
