package text

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/dejo1307/augur/pkg/detect"
	"github.com/dejo1307/augur/pkg/finding"
)

const (
	KindEscapeSeq   = finding.Kind("escape-sequence")
	KindControlChar = finding.Kind("control-character")
	KindOverwrite   = finding.Kind("carriage-return-overwrite")
)

// Control finds bytes that a terminal executes rather than prints.
//
// Every other text detector here asks what a character looks like. This one asks
// what happens when the file is displayed, and the answer is not always "it is
// displayed". `ESC[8m` turns the rest of the line invisible. `ESC]0;…BEL` retitles
// the window; `ESC]52;…` writes the system clipboard. A carriage return in the
// middle of a line makes the terminal paint the rest of the line over what it
// already printed, so a command can be shown one thing and given another — which
// is the same attack as Trojan Source with different machinery, and the reason
// `curl … | sh` and reading a file with `cat` are less different than they look.
//
// The C0 and C1 control characters get the same treatment for a duller reason:
// they render as nothing or as a placeholder, they are not whitespace, and a file
// carrying them is carrying something no editor put there.
type Control struct{}

func (Control) Name() string { return "control" }

func (Control) Applies(f detect.Format) bool { return true }

func (d Control) Detect(src *detect.Source) (finding.Set, error) {
	var out finding.Set
	for _, region := range src.Regions {
		out = append(out, d.scan(region)...)
	}
	return out, nil
}

func (d Control) scan(r detect.Region) finding.Set {
	var out finding.Set
	s := r.Text
	for i := 0; i < len(s); {
		c, size := utf8.DecodeRuneInString(s[i:])
		if size == 0 {
			break
		}

		if seq, ok := escapeAt(s, i); ok {
			out = append(out, d.reportEscape(r, i, seq))
			i += seq.length
			continue
		}

		if !isControl(c) {
			i += size
			continue
		}

		switch c {
		case '\n', '\t':
			// Structure, not payload. Tabs at the end of a line belong to the
			// Trailing detector, which claims whole runs of them.
		case '\r':
			// Two very different characters wearing one codepoint. Before a
			// newline it is half of a CRLF line ending and means nothing; in the
			// middle of a line it repaints what was already printed.
			//
			// The end-of-line zone is the boundary with the Trailing detector,
			// which owns every blank run that no reader can see. Asking the same
			// question both detectors ask keeps the two claims disjoint without
			// either of them having to know the other exists.
			if endOfLineZone(s, i) {
				break
			}
			out = append(out, d.reportOverwrite(r, i, s))
		default:
			out = append(out, d.reportControl(r, i, c, size))
		}
		i += size
	}
	return out
}

// isControl reports whether a rune is a C0 or C1 control, or DEL.
func isControl(r rune) bool {
	return r < 0x20 || r == 0x7F || (r >= 0x80 && r <= 0x9F)
}

// escape is one parsed escape sequence.
type escape struct {
	length int    // bytes, from the introducer
	kind   string // "CSI", "OSC", "DCS", "APC", "PM", "two-byte"
	body   string // the parameters, without introducer or terminator
	final  byte   // the final byte of a CSI sequence, which is what it does
}

// escapeAt parses an ANSI escape sequence starting at i, if one starts there.
//
// Parsed rather than pattern-matched because the span has to be exact: a finding
// that claims a few bytes too many or too few would either corrupt the file when
// removed or leave a fragment behind, and a fragment of an escape sequence is
// still an escape sequence.
func escapeAt(s string, i int) (escape, bool) {
	rest := s[i:]

	// The C1 controls have single-codepoint forms of the same introducers. A file
	// can use either, so both are recognised.
	switch {
	case strings.HasPrefix(rest, "\x1b["):
		return parseCSI(rest[2:], 2)
	case strings.HasPrefix(rest, "\u009b"):
		return parseCSI(rest[2:], 2) // U+009B is two bytes in UTF-8
	case strings.HasPrefix(rest, "\x1b]"):
		return parseString(rest[2:], 2, "OSC")
	case strings.HasPrefix(rest, "\x1bP"):
		return parseString(rest[2:], 2, "DCS")
	case strings.HasPrefix(rest, "\x1b^"):
		return parseString(rest[2:], 2, "PM")
	case strings.HasPrefix(rest, "\x1b_"):
		return parseString(rest[2:], 2, "APC")
	case strings.HasPrefix(rest, "\x1b") && len(rest) > 1 &&
		rest[1] >= 0x40 && rest[1] <= 0x7E:
		return escape{length: 2, kind: "two-byte", body: rest[1:2]}, true
	}
	return escape{}, false
}

// parseCSI reads a control sequence: parameter bytes, then intermediate bytes,
// then one final byte that says what it does.
func parseCSI(body string, prefix int) (escape, bool) {
	j := 0
	for j < len(body) && body[j] >= 0x30 && body[j] <= 0x3F {
		j++
	}
	params := body[:j]
	for j < len(body) && body[j] >= 0x20 && body[j] <= 0x2F {
		j++
	}
	if j >= len(body) || body[j] < 0x40 || body[j] > 0x7E {
		return escape{}, false // unterminated: not a sequence, just an ESC
	}
	return escape{length: prefix + j + 1, kind: "CSI", body: params, final: body[j]}, true
}

// parseString reads the escape sequences that carry a payload rather than a
// command — OSC, DCS, PM, APC — which run until a string terminator.
func parseString(body string, prefix int, kind string) (escape, bool) {
	for j := 0; j < len(body); j++ {
		switch {
		case body[j] == 0x07: // BEL, the terminator xterm popularised
			return escape{length: prefix + j + 1, kind: kind, body: body[:j]}, true
		case body[j] == 0x1b && j+1 < len(body) && body[j+1] == '\\': // ESC \, the standard ST
			return escape{length: prefix + j + 2, kind: kind, body: body[:j]}, true
		case body[j] == '\n':
			return escape{}, false // a payload cannot span lines; this ESC was stray
		}
	}
	return escape{}, false
}

func (d Control) reportEscape(r detect.Region, at int, e escape) finding.Finding {
	span := r.Span(at, e.length)
	label, why, sev := describeEscape(e)

	f := finding.New(d.Name(), KindEscapeSeq, finding.Terminal, sev, span, label, why).
		WithDetail(finding.NewBlob(e.length, []byte(printableEscape(r.Text[at:at+e.length])), "ansi escape"))
	if span.Exact {
		return f.Deletable()
	}
	return f.Irremovable("Found inside re-encoded text, so it can only be removed by dropping the block that contains it.")
}

// describeEscape says what the sequence does, in the words of someone explaining
// why it matters rather than in the words of the standard.
func describeEscape(e escape) (label, why string, sev finding.Severity) {
	switch e.kind {
	case "OSC":
		// Operating System Command. The dangerous one: OSC 52 writes the system
		// clipboard, OSC 8 attaches a URL to text that need not resemble it.
		what := "sets a terminal property"
		sev = finding.Concern
		switch {
		case strings.HasPrefix(e.body, "52;"):
			what = "writes to the system clipboard"
			sev = finding.Alarm
		case strings.HasPrefix(e.body, "8;"):
			what = "attaches a hyperlink to the text that follows"
			sev = finding.Alarm
		case strings.HasPrefix(e.body, "0;"), strings.HasPrefix(e.body, "1;"), strings.HasPrefix(e.body, "2;"):
			what = "renames the terminal window"
		}
		return fmt.Sprintf("terminal command (OSC): %s", what),
			"An escape sequence carrying a payload to the terminal emulator rather than text to " +
				"the screen. Nothing about it is displayed, and displaying the file is what runs it.",
			sev

	case "DCS", "APC", "PM":
		return fmt.Sprintf("terminal string (%s), %d bytes", e.kind, len(e.body)),
			"A private payload addressed to the terminal emulator. It is not displayed, its " +
				"meaning is whatever the emulator decides, and it travels inside the file as text.",
			finding.Alarm

	case "CSI":
		return describeCSI(e)
	}
	return fmt.Sprintf("escape sequence ESC %s", e.body),
		"A two-byte escape sequence, interpreted by the terminal rather than printed.",
		finding.Notice
}

func describeCSI(e escape) (label, why string, sev finding.Severity) {
	switch e.final {
	case 'm': // SGR: colours and attributes
		if hasSGRParam(e.body, 8) {
			return "ESC[8m — conceal: hides the text that follows",
				"Sets the terminal's conceal attribute, which prints the following text " +
					"invisibly. The characters are in the file and in anything that copies " +
					"from it; they are simply not shown to the person reading it.",
				finding.Alarm
		}
		return fmt.Sprintf("ESC[%sm — colour or text attribute", e.body),
			"Sets colour or emphasis for the text that follows. Ordinary in a log or a " +
				"coloured script, and worth seeing here because a foreground colour matching " +
				"the background hides text just as completely as concealing it.",
			finding.Notice

	case 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'f', 'd':
		return fmt.Sprintf("ESC[%s%c — moves the cursor", e.body, e.final),
			"Repositions the cursor, so what the terminal prints next lands on top of " +
				"something it already printed. The file and the screen stop agreeing at " +
				"this point.",
			finding.Concern

	case 'J', 'K':
		return fmt.Sprintf("ESC[%s%c — erases part of the screen", e.body, e.final),
			"Clears text the terminal has already printed. Anything erased this way was " +
				"in the file and was never read.",
			finding.Concern
	}
	return fmt.Sprintf("ESC[%s%c — control sequence", e.body, e.final),
		"A control sequence acted on by the terminal rather than printed.",
		finding.Notice
}

// hasSGRParam reports whether a select-graphic-rendition parameter list contains
// a given attribute. Parsed rather than substring-matched: "38" and "48" contain
// "8" and mean something else entirely.
func hasSGRParam(body string, want int) bool {
	for _, p := range strings.Split(body, ";") {
		if p == "" {
			continue
		}
		if n, err := strconv.Atoi(p); err == nil && n == want {
			return true
		}
	}
	return false
}

func (d Control) reportOverwrite(r detect.Region, at int, s string) finding.Finding {
	span := r.Span(at, 1)
	before := lineUpTo(s, at)
	after := lineFrom(s, at+1)

	f := finding.New(d.Name(), KindOverwrite, finding.Terminal, finding.Alarm, span,
		fmt.Sprintf("carriage return overwrites %d character(s) of this line", len([]rune(before))),
		"A carriage return that is not part of a line ending returns the cursor to the start "+
			"of the line, so a terminal prints what follows on top of what came before. The "+
			"line stored in the file and the line you see are different text.").
		WithDetail(finding.NewTable("overwrite", []finding.KV{
			{Key: "stored", Value: before + "\\r" + after},
			{Key: "displayed", Value: overwrite(before, after), Sensitive: true},
		}))

	// Shown and never fixed, and the two obvious fixes are why. Deleting the
	// carriage return runs the two halves together into a line the file never
	// contained; replacing it with a newline invents a line break that was never
	// there either. Both produce a file that says something the original did not,
	// which is the one thing cleaning is not allowed to do. Which half was meant
	// to be read is a judgment about intent, and the reader has the evidence for
	// it right here.
	return f.Irremovable(
		"Not removed automatically: deleting it would join the two halves and replacing it " +
			"with a newline would invent a line break, and only you can say which half the " +
			"line was meant to be.")
}

func (d Control) reportControl(r detect.Region, at int, c rune, size int) finding.Finding {
	span := r.Span(at, size)
	name := controlName(c)
	sev := finding.Concern
	if c == 0x00 {
		// A NUL in a text file is the byte that used to stop this tool reading the
		// file at all, and it is a well-worn way to truncate a string in whatever
		// reads it next.
		sev = finding.Alarm
	}

	f := finding.New(d.Name(), KindControlChar, finding.Invisible, sev, span,
		fmt.Sprintf("U+%04X %s", c, name),
		"A control character. It is not whitespace and not a letter: terminals and editors "+
			"each decide for themselves whether to show it, skip it, or stop reading at it.").
		WithDetail(finding.NewRunes([]rune{c}, []string{fmt.Sprintf("U+%04X %s", c, name)}))
	if span.Exact {
		return f.Deletable()
	}
	return f.Irremovable("Found inside re-encoded text.")
}

// c0Names covers the control characters worth naming. The rest are reported by
// codepoint, which is what a reader needs anyway.
var c0Names = map[rune]string{
	0x00: "NULL", 0x01: "START OF HEADING", 0x02: "START OF TEXT",
	0x03: "END OF TEXT", 0x04: "END OF TRANSMISSION", 0x05: "ENQUIRY",
	0x06: "ACKNOWLEDGE", 0x07: "BELL", 0x08: "BACKSPACE",
	0x0B: "LINE TABULATION", 0x0C: "FORM FEED", 0x0E: "SHIFT OUT",
	0x0F: "SHIFT IN", 0x1A: "SUBSTITUTE", 0x1B: "ESCAPE",
	0x7F: "DELETE",
}

func controlName(c rune) string {
	if n, ok := c0Names[c]; ok {
		return n
	}
	if c >= 0x80 && c <= 0x9F {
		return "C1 CONTROL"
	}
	return "CONTROL CHARACTER"
}

// lineUpTo returns the text from the start of the line to i.
func lineUpTo(s string, i int) string {
	start := strings.LastIndexByte(s[:i], '\n') + 1
	return s[start:i]
}

// lineFrom returns the text from i to the end of the line, stopping at the next
// carriage return so that only the segment this one paints over is shown.
func lineFrom(s string, i int) string {
	end := len(s)
	for j := i; j < len(s); j++ {
		if s[j] == '\n' || s[j] == '\r' {
			end = j
			break
		}
	}
	return s[i:end]
}

// overwrite renders what a terminal would actually display: the later text
// painted over the earlier, character by character, leaving whatever it does not
// reach.
func overwrite(before, after string) string {
	b := []rune(before)
	a := []rune(after)
	if len(a) >= len(b) {
		return string(a)
	}
	return string(append(a, b[len(a):]...))
}

// printableEscape renders an escape sequence so it can be shown without being
// executed by the terminal showing it. Displaying a finding about an escape
// sequence by printing the escape sequence would be a memorable bug.
func printableEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == 0x1b:
			b.WriteString("ESC")
		case r == 0x07:
			b.WriteString("BEL")
		case r < 0x20 || r == 0x7F:
			fmt.Fprintf(&b, "\\x%02X", r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
