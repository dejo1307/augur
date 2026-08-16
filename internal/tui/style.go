package tui

import (
	"github.com/charmbracelet/lipgloss"

	"github.com/dejo1307/augur/pkg/finding"
)

// Colours are adaptive so the viewer is legible on a light terminal and a dark
// one without asking which it is.
var (
	colFaint  = lipgloss.AdaptiveColor{Light: "#6b7280", Dark: "#8b93a1"}
	colText   = lipgloss.AdaptiveColor{Light: "#111827", Dark: "#e5e7eb"}
	colAccent = lipgloss.AdaptiveColor{Light: "#1d4ed8", Dark: "#7aa2f7"}
	colAlarm  = lipgloss.AdaptiveColor{Light: "#b91c1c", Dark: "#f7768e"}
	colWarn   = lipgloss.AdaptiveColor{Light: "#b45309", Dark: "#e0af68"}
	colOK     = lipgloss.AdaptiveColor{Light: "#15803d", Dark: "#9ece6a"}
	colRule   = lipgloss.AdaptiveColor{Light: "#d1d5db", Dark: "#3b4261"}
)

var (
	styTitle = lipgloss.NewStyle().Bold(true).Foreground(colText)
	styPath  = lipgloss.NewStyle().Foreground(colAccent).Bold(true)
	styFaint = lipgloss.NewStyle().Foreground(colFaint)
	styRule  = lipgloss.NewStyle().Foreground(colRule)
	styHelp  = lipgloss.NewStyle().Foreground(colFaint)

	styCategory = lipgloss.NewStyle().Bold(true).Foreground(colFaint)
	stySelected = lipgloss.NewStyle().Foreground(colText).Bold(true)
	styCursor   = lipgloss.NewStyle().Foreground(colAccent).Bold(true)

	styAlarm = lipgloss.NewStyle().Foreground(colAlarm).Bold(true)
	styWarn  = lipgloss.NewStyle().Foreground(colWarn)
	styOK    = lipgloss.NewStyle().Foreground(colOK).Bold(true)

	// styHiddenChar renders an invisible character's stand-in. It is the one
	// thing on screen that must never be subtle: the whole point of the viewer is
	// that these stop being invisible.
	styHiddenChar = lipgloss.NewStyle().
			Foreground(lipgloss.AdaptiveColor{Light: "#ffffff", Dark: "#1a1b26"}).
			Background(colAlarm).Bold(true)

	styPayload = lipgloss.NewStyle().Foreground(colAlarm).Bold(true)

	styPane = lipgloss.NewStyle().
		Border(lipgloss.NormalBorder(), false, false, false, true).
		BorderForeground(colRule).
		PaddingLeft(2)
)

func severityStyle(s finding.Severity) lipgloss.Style {
	switch s {
	case finding.Alarm:
		return styAlarm
	case finding.Concern:
		return styWarn
	default:
		return styFaint
	}
}

// severityMark is a one-glyph severity indicator, so the list reads at a glance
// without colour alone carrying the meaning.
func severityMark(s finding.Severity) string {
	switch s {
	case finding.Alarm:
		return "!"
	case finding.Concern:
		return "•"
	default:
		return "·"
	}
}
