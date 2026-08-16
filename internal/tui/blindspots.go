package tui

import (
	"fmt"
	"strings"

	"github.com/dejo1307/augur/internal/decode"
	"github.com/dejo1307/augur/internal/scan"
)

// blindSpots is the panel that says what augur cannot see.
//
// It is a feature, not a disclaimer. A tool that reports "clean" without naming
// its limits invites the reader to hear "clean of everything", and that is a
// stronger claim than any file inspector can make. Saying the boundary out loud is
// what makes the rest of the report worth believing.
func blindSpots() string {
	var b strings.Builder

	b.WriteString(styTitle.Render("What augur cannot see"))
	b.WriteString("\n\n")
	b.WriteString(styFaint.Render(
		"A clean report means these detectors found nothing. It does not mean the file\n" +
			"carries no mark at all. These are the things this tool structurally cannot find:"))
	b.WriteString("\n\n")

	limits := []struct{ name, why string }{
		{
			"Statistical watermarks in generated text",
			"Some text generators bias their word choice to a pattern only the generator's\n" +
				"own key can recognise. Nothing is hidden in the characters, so there is\n" +
				"nothing here to find. Only whoever holds the key can test for it.",
		},
		{
			"Watermarks carried in image pixels",
			"A mark spread across the pixel values themselves survives metadata stripping\n" +
				"and is invisible to a container inspector. augur reads containers, not\n" +
				"images, and deliberately does not attack these — see the lossless-only decision.",
		},
		{
			"Fingerprinting by wording",
			"A document individualised by rephrasing a sentence per recipient carries no\n" +
				"unusual characters at all. There is nothing to detect without the other copies.",
		},
		{
			"What an MCP server says at runtime",
			"`augur agents` reads the config that names a server, not the server. A tool's\n" +
				"name and description are sent by the process when it starts, and they go\n" +
				"straight into a model's context — so a server can describe its tools one way\n" +
				"today and another way tomorrow with no file on disk ever changing.\n" +
				"Checking the config is not checking the server.",
		},
		{
			"Formats with no handler yet",
			"PDF, Office documents, audio and video are not parsed. A file of one of those\n" +
				"types is reported by what its raw bytes reveal and nothing more.",
		},
		{
			"Encodings nobody has published",
			"Detection of hidden characters is complete for the character classes listed\n" +
				"below, but reading what they say depends on recognising the scheme.",
		},
	}

	for _, l := range limits {
		b.WriteString(styWarn.Render("  ✗ " + l.name))
		b.WriteString("\n")
		for _, line := range strings.Split(l.why, "\n") {
			b.WriteString(styFaint.Render("      " + line))
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	b.WriteString(styTitle.Render("What it does read"))
	b.WriteString("\n\n")
	for _, d := range scan.Detectors() {
		b.WriteString(styOK.Render("  ✓ "))
		b.WriteString(d.Name())
		b.WriteString("\n")
	}
	b.WriteString("\n")
	b.WriteString(styFaint.Render("  smuggling schemes it can decode:"))
	b.WriteString("\n")
	for _, s := range decode.Schemes() {
		b.WriteString(styFaint.Render(fmt.Sprintf("    · %s", s)))
		b.WriteString("\n")
	}

	b.WriteString("\n")
	b.WriteString(styHelp.Render("↑↓ scroll · any other key to go back"))
	return b.String()
}
