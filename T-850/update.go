package main

import (
	"fmt"

	tea "charm.land/bubbletea/v2"
)

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if m.exitMessage != "" {
		return m, tea.Quit
	}
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "up":
			if m.selectedMode == INIT && m.modes[INIT].Step == 3 {
				if m.cursor > 0 {
					m.cursor--
				}
				return m, nil
			}
			if m.selectedMode == LIST && m.modes[LIST].Step != 2 {
				if m.cursor > 0 {
					m.cursor--
				}
				return m, nil
			}
			if m.selectedMode == LIST_CERTS {
				if m.cursor > 0 {
					m.cursor--
				}
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
			return m, nil
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
			}
			return m, nil
		case "I":
			if m.selectedMode == LIST && m.modes[LIST].selectedKP != nil {
				m.filepicker = newFilepicker(m, []string{".pem", ".crt", ".cer", ".der"})
				m.modes[LIST].Step = 2
				return m, m.filepicker.Init()
			}
			return m, nil
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
			}

			return m, nil
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
			return m, nil
		case "down":
			if m.selectedMode == INIT && m.modes[INIT].Step == 3 {
				if m.cursor < len(m.modes)-1 {
					m.cursor++
				}
				return m, nil
			}
			if m.selectedMode == LIST && m.modes[LIST].Step != 2 {
				if m.cursor < len(m.keyPairs)-1 {
					m.cursor++
				}
				return m, nil
			}
			if m.selectedMode == LIST_CERTS {
				if m.cursor < len(m.certificates)-1 {
					m.cursor++
				}
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
