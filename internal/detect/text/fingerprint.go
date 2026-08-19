package text

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/dejo1307/augur/internal/runeinfo"
	"github.com/dejo1307/augur/pkg/detect"
	"github.com/dejo1307/augur/pkg/finding"
)

const KindFingerprint = finding.Kind("fingerprint-distribution")

// Fingerprint reports a *distribution* of invisible characters rather than an
// occurrence of one.
//
// Every other detector here answers "what is this character". That question has no
// good answer for a single zero-width space: it is a copy-paste artefact, it is
// nothing, it is a notice at most, and reporting it as anything more would be
// crying wolf. But two hundred of them, one to a line, through a document that has
// no other reason to contain any — that is not two hundred artefacts. It is one
// mark, and the thing that makes it a mark is a property no individual character
// has.
//
// This is the shape a per-recipient watermark takes when it is made of characters
// at all: sparse, invisible, regular, and individually deniable. It is also the
// one thing in this file that a reader could not have worked out for themselves
// from the list of findings, because the list is sorted by position and the
// pattern is only visible from above.
//
// Nothing here is removable and nothing here needs to be: every character in the
// distribution is already reported and already removable on its own. This finding
// removes the deniability, not the characters.
type Fingerprint struct{}

func (Fingerprint) Name() string { return "fingerprint" }

func (Fingerprint) Applies(f detect.Format) bool { return true }

// The thresholds. A watermark has to be long enough to carry an identity and
// spread out enough to survive editing, which is exactly what makes it visible
// from here — and what separates it from the handful of stray characters a word
// processor leaves behind.
const (
	minOccurrences = 6
	minLines       = 4
)

func (d Fingerprint) Detect(src *detect.Source) (finding.Set, error) {
	var out finding.Set
	for _, region := range src.Regions {
		out = append(out, d.scan(region)...)
	}
	return out, nil
}

// spread is where one codepoint turned up.
type spread struct {
	offsets []int
	lines   map[int]int // line number -> occurrences on it
}

func (d Fingerprint) scan(r detect.Region) finding.Set {
	spreads := map[rune]*spread{}
	line := 0
	spaces := 0

	prevHidden := false
	for i, c := range r.Text {
		if c == '\n' {
			line++
			prevHidden = false
			continue
		}
		if c == ' ' {
			spaces++
		}

		class := runeinfo.Classify(c)
		isolated := !prevHidden && !nextIsHidden(r.Text, i, c)
		prevHidden = class.Hidden()

		// Only isolated occurrences count. A run of hidden characters is a
		// payload and the Hidden detector already reads it out; a mark is made of
		// single characters, because a single character is what survives being
		// pasted into an editor and what nobody looks twice at.
		if !isolated {
			continue
		}
		if !class.Hidden() && class != runeinfo.ExoticSpace {
			continue
		}
		if doingItsJob(c, r.Text, i) {
			continue
		}

		s := spreads[c]
		if s == nil {
			s = &spread{lines: map[int]int{}}
			spreads[c] = s
		}
		s.offsets = append(s.offsets, i)
		s.lines[line]++
	}

	var out finding.Set
	for _, c := range sortedRunes(spreads) {
		s := spreads[c]
		if len(s.offsets) < minOccurrences || len(s.lines) < minLines {
			continue
		}
		if f, ok := d.report(r, c, s, spaces); ok {
			out = append(out, f)
		}
	}
	return out
}

func (d Fingerprint) report(r detect.Region, c rune, s *spread, spaces int) (finding.Finding, bool) {
	class := runeinfo.Classify(c)

	sev := finding.Alarm
	why := "A character that renders as nothing, repeated across the document at a cadence " +
		"no editor produces. Individually each one is deniable and this tool reports each one " +
		"as a notice; together they are a pattern, and a pattern of invisible characters " +
		"through a document is how a copy is marked so that a leak can be traced to whoever " +
		"received it."
	if class == runeinfo.ExoticSpace {
		// Typography does this legitimately and constantly — French spacing puts a
		// narrow no-break space before half the punctuation in the language — so
		// this half of the finding explains rather than accuses.
		sev = finding.Concern
		why = "A space that is not an ordinary space, used repeatedly through the document. " +
			"Typesetting does this on purpose, and so does fingerprinting: a particular " +
			"pattern of unusual spaces identifies which copy of a document a leak came from, " +
			"survives reformatting, and is invisible to the reader either way."
		if spaces > 0 && len(s.offsets)*4 > spaces {
			// Not sparse: this is how the document is typeset, not a mark hidden
			// among ordinary spaces.
			return finding.Finding{}, false
		}
	}

	perLine := "about one per line"
	if densest := maxPerLine(s.lines); densest > 1 {
		perLine = fmt.Sprintf("up to %d per line", densest)
	}

	span := r.Span(s.offsets[0], 0)
	return finding.New(d.Name(), KindFingerprint, finding.Fingerprint, sev, span,
		fmt.Sprintf("%s appears %d times across %d lines, %s",
			runeinfo.Label(c), len(s.offsets), len(s.lines), perLine),
		why).
		WithDetail(finding.NewTable("distribution", []finding.KV{
			{Key: "character", Value: runeinfo.Label(c)},
			{Key: "occurrences", Value: fmt.Sprintf("%d", len(s.offsets))},
			{Key: "lines", Value: fmt.Sprintf("%d", len(s.lines))},
			{Key: "cadence", Value: perLine, Sensitive: true},
			{Key: "offsets", Value: sampleOffsets(s.offsets)},
		})).
		Irremovable("Not removable as a pattern: each character in it is reported separately and can be removed there, which is also the only way to be sure of what was taken out."), true
}

// doingItsJob reports whether an invisible character at this position is doing
// the thing Unicode defines it for, rather than sitting in text for some other
// reason.
//
// One case, and it is the one that would otherwise make this detector useless on
// real documents: U+FE0F after a symbol is the emoji presentation selector,
// selecting the colour glyph for the character before it. A README with an emoji
// in each of six headings contains six of them, one per line, spread through the
// document — every signal this detector looks for, produced by a document doing
// nothing at all unusual. After a *letter* the same character means nothing and is
// counted, because there it is not selecting anything.
func doingItsJob(c rune, s string, i int) bool {
	if c != 0xFE0E && c != 0xFE0F {
		return false
	}
	prev, size := utf8.DecodeLastRuneInString(s[:i])
	if size == 0 {
		return false
	}
	return unicode.Is(unicode.So, prev) || unicode.Is(unicode.Sk, prev)
}

// nextIsHidden reports whether the codepoint after the one at i is also hidden,
// which is what makes this occurrence part of a run rather than a lone mark.
//
// The width comes from decoding the string rather than from the rune, and that is
// not a style preference. Ranging over a string yields U+FFFD for a byte that is
// not valid UTF-8, and U+FFFD is three bytes wide while the byte that produced it
// is one — so advancing by the rune's width walks past the end of the string. A
// region carrying invalid UTF-8 is exactly the kind of input this tool is pointed
// at, and it crashed the scan.
func nextIsHidden(s string, i int, _ rune) bool {
	_, size := utf8.DecodeRuneInString(s[i:])
	if size <= 0 || i+size >= len(s) {
		return false
	}
	for _, r := range s[i+size:] {
		return runeinfo.Classify(r).Hidden()
	}
	return false
}

func maxPerLine(lines map[int]int) int {
	densest := 0
	for _, n := range lines {
		if n > densest {
			densest = n
		}
	}
	return densest
}

func sampleOffsets(offsets []int) string {
	const show = 8
	parts := make([]string, 0, show+1)
	for i, o := range offsets {
		if i == show {
			parts = append(parts, fmt.Sprintf("… and %d more", len(offsets)-show))
			break
		}
		parts = append(parts, fmt.Sprintf("%d", o))
	}
	return strings.Join(parts, ", ")
}

func sortedRunes(m map[rune]*spread) []rune {
	out := make([]rune, 0, len(m))
	for r := range m {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
