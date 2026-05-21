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
			if m.selectedMode == LIST {
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
		case "D":
			if m.modes[LIST].selectedKP != nil && m.modes[LIST].Step >= 1 {
				deleteKeyPair(m.ctx, m.modes[LIST].selectedKP)
				return m, tea.Quit
			}
			return m, nil
		case "E":
			if m.modes[LIST].selectedKP != nil && m.modes[LIST].Step >= 1 {
				exportPublicKey(m.ctx, m.modes[LIST].selectedKP)
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
			if m.selectedMode == LIST {
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
