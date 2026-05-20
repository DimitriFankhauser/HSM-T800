package main

import (
	tea "charm.land/bubbletea/v2"
)

func (m model) View() tea.View {
	return modes[m.selectedMode].ViewHandler(m)
}
