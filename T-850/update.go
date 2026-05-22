package main

import (
	tea "charm.land/bubbletea/v2"
)

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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
				generateCfgForQuarkus(m.pathToSo, m.tokenLabel)
				generatePropertiesForQuarkus(m.pin, getKeyLabel(m.ctx, m.modes[LIST].selectedKP))
				return m, tea.Quit
			}
			return m, nil
		case "R":
			if m.selectedMode == LIST_CERTS && m.modes[LIST_CERTS].selectedCert.Certificate != nil {
				generateCSR(m.modes[LIST_CERTS].selectedCert)
				return m, tea.Quit
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
				deleteKeyPair(m.ctx, m.modes[LIST].selectedKP)
				return m, tea.Quit
			}
			if m.modes[LIST_CERTS].selectedCert.Certificate != nil && m.modes[LIST_CERTS].Step >= 1 {
				deleteCertificate(m.ctx, m.modes[LIST_CERTS].selectedCert)
			}

			return m, nil
		case "E":
			if m.modes[LIST].selectedKP != nil && m.modes[LIST].Step >= 1 {
				exportPublicKey(m.ctx, m.modes[LIST].selectedKP)
				return m, tea.Quit
			}
			if m.modes[LIST_CERTS].selectedCert.Certificate != nil && m.modes[LIST_CERTS].Step >= 1 {
				exportCertificate(m.ctx, m.modes[LIST_CERTS].selectedCert)
				return m, tea.Quit
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
			return m, tea.Quit
		}
	case tea.WindowSizeMsg:
		m.termHeight = msg.Height
	}
	return modes[m.selectedMode].Handler(msg, m)
}
