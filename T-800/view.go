package main

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

func (m model) View() tea.View {

	if int(m.mode.modeNum) == int(READ_CONFIG_USER) {
		return tea.NewView(renderQuestionnaire(m))
	}

	if int(m.mode.modeNum) == int(READ_CONFIG_FILE) {
		return tea.NewView(renderFileView(m))
	}

	return tea.NewView(renderMenu(m, m.cursor))
}

func renderFileView(m model) string {
	var s strings.Builder
	s.WriteString("\n  ")
	if m.selectedPath == "" {
		s.WriteString("Pick a file:")
	} else {
		s.WriteString("Selected file: " + m.filepicker.Styles.Selected.Render(m.selectedPath))
	}
	s.WriteString("\n\n" + m.filepicker.View() + "\n")
	return s.String()
}

func renderQuestionnaire(m model) string {
	//TODO: optionally add tooltip
	header := m.mode.options[m.cursor]
	var c *tea.Cursor
	if !m.textInput.VirtualCursor() {
		c = m.textInput.Cursor()
		c.Y += lipgloss.Height(header)
	}

	str := lipgloss.JoinVertical(lipgloss.Top, header, m.textInput.View())
	return str

}

func renderMenu(m model, cursor int) string {
	var options []string
	m.cursor = 0
	if int(m.mode.modeNum) == int(SELECT_TOKEN) {
		for i := 0; i < len(m.tokens); i++ {
			stringifiedToken := (&m.tokens[i]).String()
			options = append(options, stringifiedToken)

		}
		m.mode.options = options
	} else if m.mode.modeNum == OPERATE_ON_TOKEN && len(m.keys) > 0 {
		for i := 0; i < len(m.keys); i++ {
			stringifiedKey := (&m.keys[i]).String()
			options = append(options, stringifiedKey)
		}

	} else {
		options = m.mode.options
	}

	s := m.mode.title + "\n"
	for i, choice := range options {
		cur := " "
		if cursor == i {
			cur = "*"
		}
		s += fmt.Sprintf("%s %s\n", cur, choice)
	}
	s += fmt.Sprintf("\n%s\n", m.mode.modeNum)
	s += fmt.Sprintf("\n%s\n", m.pkcs11config)
	return s
}
