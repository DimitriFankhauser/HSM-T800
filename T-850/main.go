package main

import (
	"flag"
	"fmt"
	"os"

	tea "charm.land/bubbletea/v2"
)

func main() {
	debug := flag.Bool("debug", false, "")
	modulePath := flag.String("modulePath", "", "path to the PKCS#11 shared library (.so file)\n\t\te.g. /usr/lib64/softhsm/libsofthsm.so")
	label := flag.String("label", "", "HSM token label (skips the interactive prompt)")
	pin := flag.String("pin", "", "HSM token PIN (skips the interactive prompt)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "T-850 — interactive PKCS#11 / HSM management tool\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  go run . [options]\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.VisitAll(func(f *flag.Flag) {
			if f.Name != "debug" {
				fmt.Fprintf(os.Stderr, "  --%s\n\t%s\n", f.Name, f.Usage)
			}
		})
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  # fully non-interactive startup\n")
		fmt.Fprintf(os.Stderr, "  go run . --modulePath=/usr/lib64/softhsm/libsofthsm.so --label=Genesis --pin=123456789\n\n")
		fmt.Fprintf(os.Stderr, "  # skip only the library-path prompt\n")
		fmt.Fprintf(os.Stderr, "  go run . --modulePath=/usr/lib64/softhsm/libsofthsm.so\n\n")
	}

	flag.Parse()

	p := tea.NewProgram(initialModel(*debug, *modulePath, *label, *pin))
	p.Run()
}
