package main

import (
	"flag"

	tea "charm.land/bubbletea/v2"
)

func main() {
	debug := flag.Bool("debug", false, "enable debugging mode (skips HSM credential prompts)")
	flag.Parse()

	p := tea.NewProgram(initialModel(*debug))
	p.Run()
	/*
			finalModel, _ := p.Run()

		if m, ok := finalModel.(model); ok {

		}*/
}
