package text

import (
	"fmt"
	"unicode/utf8"

	"github.com/dejo1307/augur/internal/runeinfo"
	"github.com/dejo1307/augur/pkg/detect"
	"github.com/dejo1307/augur/pkg/finding"
)

const (
	KindExoticSpace  = finding.Kind("exotic-space")
	KindLineSeparato = finding.Kind("line-separator")
)

// Space finds whitespace that is not U+0020 and line breaks that are not U+000A.
//
// Mostly benign and mostly reported as a notice: word processors emit non-breaking
// spaces constantly. It earns its place for two reasons. Exotic spaces are the
// low-effort way to fingerprint a document — a particular pattern of U+2009 versus
// U+0020 identifies which copy leaked, and it survives reformatting. And they
// break exact-match search, so a reader who cannot find a string they can plainly
// see has usually met one of these.
//
// These are replaced rather than deleted: dropping a space joins two words.
type Space struct{}

func (Space) Name() string { return "space" }

func (Space) Applies(f detect.Format) bool { return true }

func (d Space) Detect(src *detect.Source) (finding.Set, error) {
	var out finding.Set
	for _, region := range src.Regions {
		for i, r := range region.Text {
			class := runeinfo.Classify(r)
			if class != runeinfo.ExoticSpace && class != runeinfo.LineSep {
				continue
			}
			// Trailing whitespace belongs to the Trailing detector, whole runs at
			// a time. Without this boundary both detectors claim the same
			// character at the end of a line, and worse, replacing it with an
			// ordinary space creates fresh trailing whitespace that the first
			// clean pass has already gone past — so cleaning would not converge.
			//
			// Neither detector has to ask the other anything to honour this: the
			// rule is a property of the text, and both can see the text.
			if class == runeinfo.ExoticSpace && endOfLineZone(region.Text, i) {
				continue
			}
			span := region.Span(i, utf8.RuneLen(r))

			kind, cat, repl, why := KindExoticSpace, finding.Whitespace, []byte(" "),
				"Looks like an ordinary space but is a different character, so exact-match "+
					"search will not find text that contains it. A distinctive pattern of these "+
					"also identifies which copy of a document a leak came from."
			if class == runeinfo.LineSep {
				kind, repl = KindLineSeparato, []byte("\n")
				why = "Breaks the line when displayed but is not a newline, so tools that split " +
					"on newlines see one line where a reader sees two."
			}

			f := finding.New(d.Name(), kind, cat, finding.Notice, span,
				runeinfo.Label(r),
				why).
				WithDetail(finding.NewRunes([]rune{r}, []string{runeinfo.Label(r)}))
			if span.Exact {
				f = f.ReplaceableWith(repl)
			} else {
				f = f.Irremovable("Found inside re-encoded text.")
			}
			out = append(out, f)
		}
	}
	return out, nil
}

// Trailing finds runs of whitespace at the end of a line.
//
// A separate detector from Space because it is a different claim: not "this
// character is unusual" but "this position is unusual". Trailing whitespace is the
// oldest text steganography there is — a pattern of spaces and tabs after the
// visible end of each line carries bits, and no renderer will ever show it.
type Trailing struct{}

func (Trailing) Name() string { return "trailing-space" }

func (Trailing) Applies(f detect.Format) bool { return true }

// isBlank reports whether a rune is whitespace for the purpose of "trailing".
// Exotic spaces count: a line ending in a non-breaking space is trailing
// whitespace just as much as one ending in an ordinary space, and treating it
// otherwise is what let the two detectors disagree about who owned it.
func isBlank(r rune) bool {
	return r == ' ' || r == '\t' || r == '\r' || runeinfo.Classify(r) == runeinfo.ExoticSpace
}

// endOfLineZone reports whether byte i lies in the stretch at the end of a line
// that contains nothing a reader can see.
//
// Hidden characters count as part of the zone even though they are not
// whitespace, and that is the subtle half of this. A zero-width space sitting
// between a trailing space and the newline would otherwise shield that space from
// being called trailing — and then removing the zero-width space, which some other
// detector owns, would expose fresh trailing whitespace that the same clean pass
// had already walked past. The file would need a second pass to settle, and the
// tool would report a file as verified while a re-scan disagreed.
//
// Deciding it this way needs no coordination between detectors: the zone is a
// property of the text, and every detector can see the text.
func endOfLineZone(s string, i int) bool {
	for _, r := range s[i:] {
		if r == '\n' {
			return true
		}
		if !isBlank(r) && !runeinfo.Classify(r).Invisible() {
			return false
		}
	}
	return true // end of file counts as end of line
}

// blankRun is a stretch of whitespace inside a line's end-of-line zone.
type blankRun struct {
	at   int // byte offset within the line
	text string
}

// blankRuns returns the maximal whitespace stretches of line[from:], splitting
// wherever a hidden character interrupts them. Splitting rather than absorbing
// keeps every span claimed by exactly one detector.
func blankRuns(line string, from int) []blankRun {
	var out []blankRun
	start := -1
	for i, r := range line[from:] {
		if isBlank(r) {
			if start < 0 {
				start = from + i
			}
			continue
		}
		if start >= 0 {
			out = append(out, blankRun{at: start, text: line[start : from+i]})
			start = -1
		}
	}
	if start >= 0 {
		out = append(out, blankRun{at: start, text: line[start:]})
	}
	return out
}

func (d Trailing) Detect(src *detect.Source) (finding.Set, error) {
	var out finding.Set
	for _, region := range src.Regions {
		s := region.Text
		lineStart := 0
		for i := 0; i <= len(s); i++ {
			if i < len(s) && s[i] != '\n' {
				continue
			}
			line := s[lineStart:i]

			// Walk back over everything invisible to find where the zone starts.
			// Hidden characters are stepped over, not claimed: they belong to the
			// Hidden detector, and claiming them here would mean two detectors
			// producing overlapping edits for the same bytes.
			zone := len(line)
			for zone > 0 {
				r, size := utf8.DecodeLastRuneInString(line[:zone])
				if !isBlank(r) && !runeinfo.Classify(r).Invisible() {
					break
				}
				zone -= size
			}

			for _, run := range blankRuns(line, zone) {
				// A bare \r is the other half of a CRLF line ending, not a payload.
				if run.text == "\r" {
					continue
				}
				span := region.Span(lineStart+run.at, len(run.text))
				f := finding.New(d.Name(), finding.Kind("trailing-whitespace"), finding.Whitespace,
					finding.Notice, span,
					fmt.Sprintf("%d trailing whitespace character(s)", len([]rune(run.text))),
					"Sits past the visible end of the line where no renderer will show it. "+
						"Usually an editor artefact; a consistent pattern of spaces and tabs "+
						"across many lines is one of the oldest ways to hide bits in a text file.").
					WithDetail(finding.NewBlob(len(run.text), []byte(run.text), ""))
				if span.Exact {
					f = f.Deletable()
				} else {
					f = f.Irremovable("Found inside re-encoded text.")
				}
				out = append(out, f)
			}
			lineStart = i + 1
		}
	}
	return out, nil
}
