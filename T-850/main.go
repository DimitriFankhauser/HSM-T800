package main

import (
	"fmt"

	tea "charm.land/bubbletea/v2"
)

func main() {
	p := tea.NewProgram(initialModel())
	finalModel, _ := p.Run()
	if m, ok := finalModel.(model); ok {
		fmt.Println(m.pathToSo)
		fmt.Println(m.pin)
		fmt.Println(m.tokenLabel)
		fmt.Println(m.keyPairs)
		fmt.Println(m.errorMsg)

	}
}
