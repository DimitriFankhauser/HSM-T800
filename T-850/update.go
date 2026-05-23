package main

import (
	"fmt"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
)

func cursorUp(cursor int) int {
	if cursor > 0 {
		return cursor - 1
	}
	return cursor
}

func cursorDown(cursor, max int) int {
	if cursor < max {
		return cursor + 1
	}
	return cursor
}

// navigationMax returns the cursor upper bound
func navigationMax(m model) (max int, success bool) {
	switch {
	case m.selectedMode == INIT && m.modes[INIT].Step == 3:
		return 3, true // 4 menu items: IMPORT, LIST, LIST_CERTS, CREATE_KEYPAIR
	case m.selectedMode == LIST && m.modes[LIST].Step != 2:
		return len(m.keyPairs) - 1, true
	case m.selectedMode == LIST_CERTS:
		return len(m.certificates) - 1, true
	case m.selectedMode == SIGN && m.modes[SIGN].Step == 0:
		return len(signHashOptions) - 1, true
	case m.selectedMode == CREATE_KEYPAIR && m.modes[CREATE_KEYPAIR].Step == 1:
		return len(keyTypeOptions) - 1, true
	case m.selectedMode == CREATE_KEYPAIR && m.modes[CREATE_KEYPAIR].Step == 2:
		if m.modes[CREATE_KEYPAIR].KeyType == "ECC" {
			return len(eccKeyOptions) - 1, true
		}
		return len(rsaKeyOptions) - 1, true
	}
	return 0, false
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if m.exitMessage != "" {
		return m, tea.Quit
	}
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "up":
			if _, ok := navigationMax(m); ok {
				m.cursor = cursorUp(m.cursor)
				return m, nil
			}
		case "Q":
			if m.modes[LIST].selectedKP != nil && m.modes[LIST].Step >= 1 {
				if err := generateCfgForQuarkus(m.pathToSo, m.tokenLabel); err != nil {
					m.exitMessage = err.Error()
					m.FinishError = true
					return m, nil
				}
				if err := generatePropertiesForQuarkus(m.pin, getKeyLabel(m.ctx, m.modes[LIST].selectedKP)); err != nil {
					m.exitMessage = err.Error()
					m.FinishError = true
					return m, nil
				}
				m.exitMessage = "Successfully generated files for Quarkus"
				m.FinishError = false
				return m, nil
			}
		case "R":
			if m.selectedMode == LIST_CERTS && m.modes[LIST_CERTS].selectedCert.Certificate != nil {
				certPath, err := generateCSR(m.modes[LIST_CERTS].selectedCert)
				if err != nil {
					m.exitMessage = err.Error()
					m.FinishError = true
					return m, nil
				}
				m.exitMessage = fmt.Sprintf("Certificate generated for Quarkus %s", certPath)
				m.FinishError = false
				return m, nil
			}
		case "S":
			if m.selectedMode == LIST && m.modes[LIST].selectedKP != nil && m.modes[LIST].Step >= 1 {
				sign := m.modes[SIGN]
				sign.SignFiles = nil
				sign.SigningKey = m.modes[LIST].selectedKP
				sign.Step = 0
				m.modes[SIGN] = sign
				m.selectedMode = SIGN
				m.cursor = 0
				return m, nil
			}
		case "I":
			if m.selectedMode == LIST && m.modes[LIST].selectedKP != nil {
				m.filepicker = newFilepicker(m, []string{".pem", ".crt", ".cer", ".der"})
				m.modes[LIST].Step = 2
				return m, m.filepicker.Init()
			}
		case "D":
			if m.modes[LIST].selectedKP != nil && m.modes[LIST].Step >= 1 {
				exitmsg, err := deleteKeyPair(m.ctx, m.modes[LIST].selectedKP)
				if err != nil {
					m.exitMessage = err.Error()
					m.FinishError = true
					return m, nil
				}
				m.exitMessage = exitmsg
				m.FinishError = false
				return m, nil
			}
			if m.modes[LIST_CERTS].selectedCert.Certificate != nil && m.modes[LIST_CERTS].Step >= 1 {
				exitmsg, err := deleteCertificate(m.ctx, m.modes[LIST_CERTS].selectedCert)
				if err != nil {
					m.exitMessage = err.Error()
					m.FinishError = true
					return m, nil
				}
				m.exitMessage = exitmsg
				m.FinishError = false
				return m, nil
			}
		case "E":
			if m.modes[LIST].selectedKP != nil && m.modes[LIST].Step >= 1 {
				exportPath, err := exportPublicKey(m.ctx, m.modes[LIST].selectedKP)
				if err != nil {
					m.exitMessage = err.Error()
					m.FinishError = true
					return m, nil
				}
				m.exitMessage = fmt.Sprintf("Successfully exported public key to %s", exportPath)
				m.FinishError = false
				return m, nil
			}
			if m.modes[LIST_CERTS].selectedCert.Certificate != nil && m.modes[LIST_CERTS].Step >= 1 {
				exportPath, err := exportCertificate(m.ctx, m.modes[LIST_CERTS].selectedCert)
				if err != nil {
					m.exitMessage = err.Error()
					m.FinishError = true
					return m, nil
				}
				m.exitMessage = fmt.Sprintf("Successfully exported Certificate to %s", exportPath)
				m.FinishError = false
				return m, nil
			}
		case "down":
			if max, ok := navigationMax(m); ok {
				m.cursor = cursorDown(m.cursor, max)
				return m, nil
			}
		case "esc":
			if m.selectedMode != INIT {
				m.selectedMode = INIT
				m.modes[INIT].Step = 3
				m.cursor = 0
				m.errorMsg = ""
				m.textInput.Reset()
				m.textInput.EchoMode = textinput.EchoNormal
				return m, nil
			}
		case "enter":
			return modes[m.selectedMode].Handler(msg, m)
		case "ctrl+q":
			m.exitMessage = "Quitting T-800"
			m.FinishError = false
			return m, nil
		}
	case tea.WindowSizeMsg:
		m.termHeight = msg.Height
	}
	return modes[m.selectedMode].Handler(msg, m)
}
