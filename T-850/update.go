package main

import tea "charm.land/bubbletea/v2"

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "up":
			if m.cursor > 0 {
				m.cursor--
			}
			return m, nil
		case "down":
			if m.cursor < len(m.modes)-1 {
				m.cursor++
			}
			return m, nil
		case "enter":
			return modes[m.selectedMode].Handler(msg, m)
		case "ctrl+q":
			return m, tea.Quit
		}
	}
	return modes[m.selectedMode].Handler(msg, m)

}
