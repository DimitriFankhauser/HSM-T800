package main

import (
	"fmt"

	tea "charm.land/bubbletea/v2"
)

func main() {
	p := tea.NewProgram(initialModel())
	finalModel, _ := p.Run()
	if m, ok := finalModel.(model); ok {
		fmt.Println("Goodbye!")
		fmt.Println(m.pkcs11config)
		fmt.Println(len(m.tokens))
		fmt.Println(len(m.mode.options))
	}
}
