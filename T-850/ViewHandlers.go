package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"os"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/ThalesGroup/crypto11"
)

const certDateFormat = "2006-01-02"

func welcomeScreen() string {
	b, err := os.ReadFile("welcome.txt")
	if err != nil {
		panic(err)
	}
	return string(b)
}

func finalScreen(goodbyeMessage string) tea.View {
	var s string = goodbyeMessage
	s += "\n Goodbye!"
	return tea.NewView(s)
}

func errorScreen(userinput string) tea.View {
	return tea.NewView("ERROR")
}

func HandleViewInit(m model) tea.View {

	if m.modes[INIT].Step == -1 {
		var s string = "WELCOME TO \n"
		s += welcomeScreen()
		return tea.NewView(s)
	}

	if m.modes[INIT].Step == 0 {
		header := "Enter the Path to your PKCS11-Library"
		var c *tea.Cursor
		if !m.textInput.VirtualCursor() {
			c = m.textInput.Cursor()
			c.Y += lipgloss.Height(header)
		}
		parts := []string{header, m.textInput.View()}
		if m.errorMsg != "" {
			parts = append(parts, lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Render(m.errorMsg))
		}
		return tea.NewView(lipgloss.JoinVertical(lipgloss.Top, parts...))
	}

	if m.modes[INIT].Step == 1 {
		header := "Enter Token Label"
		var c *tea.Cursor
		if !m.textInput.VirtualCursor() {
			c = m.textInput.Cursor()
			c.Y += lipgloss.Height(header)
		}
		parts := []string{header, m.textInput.View()}
		if m.errorMsg != "" {
			parts = append(parts, lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Render(m.errorMsg))
		}
		return tea.NewView(lipgloss.JoinVertical(lipgloss.Top, parts...))
	}

	if m.modes[INIT].Step == 2 {
		header := "Enter your PIN"
		var c *tea.Cursor
		if !m.textInput.VirtualCursor() {
			c = m.textInput.Cursor()
			c.Y += lipgloss.Height(header)
		}
		parts := []string{header, m.textInput.View()}
		if m.errorMsg != "" {
			parts = append(parts, lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Render(m.errorMsg))
		}
		return tea.NewView(lipgloss.JoinVertical(lipgloss.Top, parts...))
	}

	var s string
	for i, choice := range m.modes[1:SIGN] {
		cur := " "
		if m.cursor == i {
			cur = "*"
		}
		s += fmt.Sprintf("%s %s\n", cur, choice.Name)
	}
	return tea.NewView(s)
}

func getKeyLabel(ctx *crypto11.Context, kp crypto11.Signer) string {
	attr, err := ctx.GetAttribute(kp, crypto11.CkaLabel)
	if err != nil || attr == nil {
		return "(unknown)"
	}
	return string(attr.Value)
}

func HandleViewList(m model) tea.View {
	if m.modes[LIST].Step == 2 {
		return tea.NewView(lipgloss.JoinVertical(lipgloss.Top, "Select Certificate to Import", m.filepicker.View()))
	}

	var s string

	s += fmt.Sprintf("%-20s %-10s %-15s\n", "Label", "Key Type", "Key Length")
	s += fmt.Sprintln(strings.Repeat("-", 45))

	for i, kp := range m.keyPairs {
		cur := " "
		if m.cursor == i {
			cur = "*"
		}
		pub := kp.Public()

		var keyType string
		var keyLength int

		switch k := pub.(type) {
		case *rsa.PublicKey:
			keyType = "RSA"
			keyLength = k.N.BitLen()
		case *ecdsa.PublicKey:
			keyType = "EC"
			keyLength = k.Curve.Params().BitSize
		default:
			keyType = "Unknown"
			keyLength = 0
		}

		label := getKeyLabel(m.ctx, kp)
		s += fmt.Sprintf("%-2s %-20s %-10s %d bits\n", cur, label, keyType, keyLength)
	}
	if m.modes[LIST].selectedKP == nil {
		s += fmt.Sprintf("Press 'enter' to select a KeyPair")
	} else if m.modes[LIST].selectedKP != nil {
		red := lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
		s += fmt.Sprintf("%s to generate files for Quarkus \n", red.Render("[Q]"))
		s += fmt.Sprintf("%s to delete the KeyPair \n", red.Render("[D]"))
		s += fmt.Sprintf("%s to export the Public Key \n", red.Render("[E]"))
		s += fmt.Sprintf("%s to import a certificate for this KeyPair \n", red.Render("[I]"))
		s += fmt.Sprintf("%s to create a Signature with this KeyPair \n", red.Render("[S]"))

	}

	return tea.NewView(s)
}
func HandleViewListCerts(m model) tea.View {
	var s string

	s += fmt.Sprintf("%-20s %-30s %-30s %-12s\n", "Key Label", "Subject", "Issuer", "Expires")
	s += fmt.Sprintln(strings.Repeat("-", 92))

	for i, tlsCert := range m.certificates {
		cur := " "
		if m.cursor == i {
			cur = "*"
		}
		leaf := tlsCert.Leaf
		if leaf == nil {
			continue
		}
		keyLabel := "(unknown)"
		if signer, ok := tlsCert.PrivateKey.(crypto11.Signer); ok {
			keyLabel = getKeyLabel(m.ctx, signer)
		}
		subject := leaf.Subject.CommonName
		issuer := leaf.Issuer.CommonName
		expiry := leaf.NotAfter.Format(certDateFormat)
		s += fmt.Sprintf("%-2s %-20s %-30s %-30s %-12s\n", cur, keyLabel, subject, issuer, expiry)

	}
	if m.modes[LIST_CERTS].selectedCert.Certificate == nil {
		s += fmt.Sprintf("Press 'enter' to select a Certificate")
	} else if m.modes[LIST_CERTS].selectedCert.Certificate != nil {
		red := lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
		s += fmt.Sprintf("%s to create a (signed) CSR \n", red.Render("[R]"))
		s += fmt.Sprintf("%s to export the Certificate \n", red.Render("[E]"))
		s += fmt.Sprintf("%s to delete the Certificate \n", red.Render("[D]"))
	}
	return tea.NewView(s)

}
func HandleViewKeyPair(m model) tea.View {
	var s string
	s = "Not implemented"
	return tea.NewView(s)
}

func HandleViewSign(m model) tea.View {
	red := lipgloss.NewStyle().Foreground(lipgloss.Color("196"))

	var s string
	s += fmt.Sprintf("Signing with key: %s\n\n", getKeyLabel(m.ctx, m.modes[SIGN].SigningKey))

	if m.modes[SIGN].Step == 0 {
		s += "Select hash algorithm:\n\n"
		for i, opt := range signHashOptions {
			cur := " "
			if m.cursor == i {
				cur = "*"
			}
			s += fmt.Sprintf("%s %s\n", cur, opt.label)
		}
		return tea.NewView(s)
	}

	if len(m.modes[SIGN].SignFiles) > 0 {
		s += "Selected files/folders:\n"
		for _, f := range m.modes[SIGN].SignFiles {
			s += fmt.Sprintf("  %s\n", f)
		}
		s += "\n"
	}

	if m.errorMsg != "" {
		s += lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Render(m.errorMsg) + "\n\n"
	}

	s += fmt.Sprintf("Select files to sign. Press %s when done.\n\n",
		red.Render("[Tab]"))
	s += m.filepicker.View()
	return tea.NewView(s)
}
func HandleViewImport(m model) tea.View {
	if m.modes[IMPORT].Step == 0 {
		header := "Enter Key Label"
		var c *tea.Cursor
		if !m.textInput.VirtualCursor() {
			c = m.textInput.Cursor()
			c.Y += lipgloss.Height(header)
		}
		parts := []string{header, m.textInput.View()}
		if m.errorMsg != "" {
			parts = append(parts, lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Render(m.errorMsg))
		}
		return tea.NewView(lipgloss.JoinVertical(lipgloss.Top, parts...))
	}

	if m.modes[IMPORT].Step == 1 {
		header := "Select Certificate File"
		return tea.NewView(lipgloss.JoinVertical(lipgloss.Top, header, m.filepicker.View()))
	}

	if m.modes[IMPORT].Step == 2 {
		return tea.NewView(lipgloss.JoinVertical(lipgloss.Top, "Select Private Key File", m.filepicker.View()))
	}

	if m.modes[IMPORT].Step == 3 {
		return tea.NewView(lipgloss.JoinVertical(lipgloss.Top, "Select Public Key File", m.filepicker.View()))
	}

	return tea.NewView("Not implemented")
}
