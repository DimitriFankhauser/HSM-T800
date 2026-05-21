package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/ThalesGroup/crypto11"
)

func HandleViewInit(m model) tea.View {
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
	for i, choice := range m.modes[1:] {
		cur := " "
		if m.cursor == i {
			cur = "*"
		}
		s += fmt.Sprintf("%s %s\n", cur, choice.Name)
	}
	s += fmt.Sprintf("\nCurrent mode:\n%s", modes[m.selectedMode].Name)
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
	var s string

	s += fmt.Sprintf("%-20s %-10s %-15s\n", "Label", "Key Type", "Key Length")
	s += fmt.Sprintln(strings.Repeat("-", 45))

	for _, kp := range m.keyPairs {
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
		s += fmt.Sprintf("%-20s %-10s %d bits\n", label, keyType, keyLength)
	}
	return tea.NewView(s)
}
func HandleViewKeyPair(m model) tea.View {
	var s string
	s = "Not implemented"
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
