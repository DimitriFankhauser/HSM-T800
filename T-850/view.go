package main

import (
	tea "charm.land/bubbletea/v2"
)

func (m model) View() tea.View {
	if m.exitMessage != "" {
		return finalScreen(m.exitMessage)
	}
	return modes[m.selectedMode].ViewHandler(m)
}
