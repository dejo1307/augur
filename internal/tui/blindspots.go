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
			"Statistical watermarks in generated text (SynthID and its kind)",
			"Some text generators bias their word choice to a pattern only the generator's\n" +
				"own key can recognise. Nothing is hidden in the characters — the watermark is\n" +
				"in which ordinary words were chosen — so there is nothing here to find, and no\n" +
				"amount of looking at the characters will change that. Only whoever holds the\n" +
				"key can test for it. Anything claiming to detect one by reading the text is\n" +
				"guessing.\n" +
				"A Content Credential is the opposite case and augur does read those: it is\n" +
				"characters, in the file, saying what made it — see the provenance findings.",
		},
		{
			"Whether a signature or a certificate is genuine",
			"A Content Credential is signed, and augur reads the certificate and prints who\n" +
				"it says signed. It does not verify the signature and does not check the\n" +
				"certificate against any trust list, because it ships with none — so \"signed\n" +
				"by\" means \"this file says so\", not \"this was checked\". The one part of a\n" +
				"credential augur does verify for itself is the hard binding: whether the file\n" +
				"still hashes to what the claim covered. That needs no key and no network.",
		},
		{
			"A credential kept somewhere other than the file",
			"A file can point at its manifest instead of carrying it — a URL in a comment, a\n" +
				"link element, a sidecar. augur reports the pointer and does not follow it:\n" +
				"this tool reads the bytes it was given and makes no network requests, which\n" +
				"is a property worth more than the extra coverage would be.",
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
			"Documents are read, never written",
			"PDFs and Office documents are parsed and reported in full, and nothing in one\n" +
				"is removable. A PDF records the byte offset of every object in a table and an\n" +
				"Office file is a compressed archive, so taking anything out means rebuilding\n" +
				"the document rather than editing it — and a rebuilt file cannot be checked\n" +
				"against the original the way an edited one can.",
		},
		{
			"What a page would look like if it were rendered",
			"Hidden markup is found by what the source says: an inline style, a hidden\n" +
				"attribute, a comment. Text hidden by a rule in a separate stylesheet, or by\n" +
				"being drawn underneath an image or off the edge of a PDF page, is invisible\n" +
				"to a reader of the source — which is what this is.",
		},
		{
			"Formats with no handler yet",
			"Audio, video, archives and fonts are not parsed. A file of one of those types\n" +
				"is reported by what its raw bytes reveal and nothing more.",
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
