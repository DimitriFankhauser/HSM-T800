package main

import (
	tea "charm.land/bubbletea/v2"
)

func (m model) View() tea.View {
	if m.exitMessage != "" {
		return finalScreen(m.exitMessage)
	}
	v := modes[m.selectedMode].ViewHandler(m)
	if m.selectedMode != INIT {
		v.Content += "\n\n[esc] Back to menu"
	}
	return v
}
