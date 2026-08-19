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

// spread is where a family of codepoints turned up.
//
// Keyed by family rather than by codepoint, and that is the whole of the fix for
// the case this detector was blind to. A mark that varies which character it uses
// — which is how you carry more than one bit per position — divides its own
// evidence between codepoints, and a threshold applied to each one separately
// then sees several small piles instead of one mark. Alternation is what makes a
// distribution *more* obviously deliberate, not less; counting it per codepoint
// inverted that.
type spread struct {
	offsets []int
	lines   map[int]int  // line number -> occurrences on it
	runes   map[rune]int // codepoint -> occurrences of it
	spaces  int          // of the offsets, how many are exotic spaces
}

func newSpread() *spread {
	return &spread{lines: map[int]int{}, runes: map[rune]int{}}
}

func (s *spread) add(c rune, class runeinfo.Class, offset, line int) {
	s.offsets = append(s.offsets, offset)
	s.lines[line]++
	s.runes[c]++
	if class == runeinfo.ExoticSpace {
		s.spaces++
	}
}

// alphabet returns the distinct codepoints in the spread, in codepoint order.
func (s *spread) alphabet() []rune {
	out := make([]rune, 0, len(s.runes))
	for r := range s.runes {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// big reports whether the spread is long enough and wide enough to be a mark at
// all, and whether its codepoints *repeat*.
//
// The repetition test is what keeps grouping by family from inventing findings.
// A mark reuses a small alphabet: that is what an alphabet is for. Eight distinct
// private-use codepoints, one to a line, is not a mark repeating itself — it is a
// glyph font being used, which is what a shell prompt or a documentation page
// with icons in it looks like from here, and those were silent before this
// detector learned to group.
func (s *spread) big() bool {
	return len(s.offsets) >= minOccurrences &&
		len(s.lines) >= minLines &&
		len(s.offsets) >= 2*len(s.runes)
}

func (d Fingerprint) scan(r detect.Region) finding.Set {
	byClass := map[runeinfo.Class]*spread{}
	pooled := newSpread()
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

		s := byClass[class]
		if s == nil {
			s = newSpread()
			byClass[class] = s
		}
		s.add(c, class, i, line)
		pooled.add(c, class, i, line)
	}

	var out finding.Set
	for _, class := range sortedClasses(byClass) {
		if f, ok := d.report(r, class, byClass[class], spaces); ok {
			out = append(out, f)
		}
	}
	if len(out) > 0 {
		return out
	}

	// Nothing tripped one family, so ask the question one level up: a mark is
	// free to mix a no-break space into a run of zero-width spaces, and doing so
	// defeats grouping by family for exactly the reason grouping by codepoint was
	// defeated. This only runs when every family was individually quiet — if one
	// already fired, the reader knows the document is marked and restating the
	// same characters pooled together is noise.
	if len(pooled.runes) > 1 {
		if f, ok := d.report(r, runeinfo.Normal, pooled, spaces); ok {
			out = append(out, f)
		}
	}
	return out
}

// report turns a spread into a finding. class is the family the spread belongs
// to, or runeinfo.Normal for the cross-family pool, which has no single family to
// name.
func (d Fingerprint) report(r detect.Region, class runeinfo.Class, s *spread, spaces int) (finding.Finding, bool) {
	if !s.big() {
		return finding.Finding{}, false
	}
	alphabet := s.alphabet()

	// Typesetting produces exotic spaces legitimately and constantly, so the
	// sparse test asks whether these are hiding among ordinary spaces or are
	// simply how the document is spaced. Measured over the exotic spaces in the
	// spread rather than over all of it: in the cross-family pool the zero-width
	// characters are not the ones typesetting can explain, and letting them count
	// towards a typesetting quota would let a heavily spaced document argue its
	// way out of a mark it did not produce.
	if s.spaces == len(s.offsets) && spaces > 0 && s.spaces*4 > spaces {
		return finding.Finding{}, false
	}

	sev, label, why := d.describe(class, s, alphabet)

	span := r.Span(s.offsets[0], 0)
	rows := []finding.KV{
		{Key: "character", Value: runeinfo.Label(alphabet[0])},
		{Key: "occurrences", Value: fmt.Sprintf("%d", len(s.offsets))},
		{Key: "lines", Value: fmt.Sprintf("%d", len(s.lines))},
		{Key: "cadence", Value: cadence(s), Sensitive: true},
		{Key: "offsets", Value: sampleOffsets(s.offsets)},
	}
	if len(alphabet) > 1 {
		rows[0] = finding.KV{Key: "alphabet", Value: alphabetBreakdown(alphabet, s.runes), Sensitive: true}
	}

	return finding.New(d.Name(), KindFingerprint, finding.Fingerprint, sev, span, label, why).
		WithDetail(finding.NewTable("distribution", rows)).
		Irremovable("Not removable as a pattern: each character in it is reported separately and can be removed there, which is also the only way to be sure of what was taken out."), true
}

// describe picks the severity and the words, which vary along one axis: whether
// the spread is one character repeated or several rotated.
//
// One exotic space repeated is typography as often as it is a mark — French
// spacing puts a narrow no-break space before half the punctuation in the
// language — so that half explains rather than accuses. Three of them rotating
// through a document is not typography at all: a typesetter picks the space the
// context calls for and picks the same one every time that context recurs.
// Rotation is a choice of symbol from an alphabet, and an alphabet is for
// spelling something.
func (d Fingerprint) describe(class runeinfo.Class, s *spread, alphabet []rune) (finding.Severity, string, string) {
	n, lines := len(s.offsets), len(s.lines)

	if len(alphabet) == 1 {
		c := alphabet[0]
		label := fmt.Sprintf("%s appears %d times across %d lines, %s",
			runeinfo.Label(c), n, lines, cadence(s))
		if class == runeinfo.ExoticSpace {
			return finding.Concern, label,
				"A space that is not an ordinary space, used repeatedly through the document. " +
					"Typesetting does this on purpose, and so does fingerprinting: a particular " +
					"pattern of unusual spaces identifies which copy of a document a leak came from, " +
					"survives reformatting, and is invisible to the reader either way."
		}
		return finding.Alarm, label,
			"A character that renders as nothing, repeated across the document at a cadence " +
				"no editor produces. Individually each one is deniable and this tool reports each one " +
				"as a notice; together they are a pattern, and a pattern of invisible characters " +
				"through a document is how a copy is marked so that a leak can be traced to whoever " +
				"received it."
	}

	kinds := make([]string, 0, len(alphabet))
	for _, c := range alphabet {
		kinds = append(kinds, fmt.Sprintf("U+%04X", c))
	}
	noun := "invisible character"
	if class != runeinfo.Normal {
		noun = class.Noun()
	}
	label := fmt.Sprintf("%d kinds of %s (%s) appear %d times across %d lines, %s",
		len(alphabet), noun, strings.Join(kinds, ", "), n, lines, cadence(s))

	return finding.Alarm, label,
		"Several different characters that render as nothing or as an ordinary space, " +
			"rotating through the document at a steady cadence. A single repeated one is " +
			"deniable and a word processor will produce it; a rotation is not, because " +
			"choosing between interchangeable invisible characters position by position is " +
			"how a value gets spelled out. This is the shape of a per-recipient mark, and " +
			"varying the character is what makes it survive a reader who knows to look for " +
			"one of them."
}

func cadence(s *spread) string {
	if densest := maxPerLine(s.lines); densest > 1 {
		return fmt.Sprintf("up to %d per line", densest)
	}
	return "about one per line"
}

func alphabetBreakdown(alphabet []rune, counts map[rune]int) string {
	parts := make([]string, 0, len(alphabet))
	for _, c := range alphabet {
		parts = append(parts, fmt.Sprintf("%s ×%d", runeinfo.Label(c), counts[c]))
	}
	return strings.Join(parts, ", ")
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

func sortedClasses(m map[runeinfo.Class]*spread) []runeinfo.Class {
	out := make([]runeinfo.Class, 0, len(m))
	for c := range m {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
