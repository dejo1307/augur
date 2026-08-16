package text

import (
	"fmt"
	"unicode"
	"unicode/utf8"

	"github.com/dejo1307/augur/internal/runeinfo"
	"github.com/dejo1307/augur/pkg/detect"
	"github.com/dejo1307/augur/pkg/finding"
)

const KindStyledWord = finding.Kind("styled-letters")

// Styled finds words spelled in one of Unicode's alternate copies of the Latin
// alphabet — mathematical bold, fraktur, double-struck, circled, fullwidth, small
// capitals — which read as ordinary English and compare equal to nothing.
//
// It exists because the mixed-script detector structurally cannot see this, and
// the reason is worth stating: the Unicode script property of U+1D400
// MATHEMATICAL BOLD CAPITAL A is Common, not Latin. A word spelled entirely in
// mathematical bold does not mix scripts. It has one script, and that script is
// "no script in particular", so a rule built on script comparison has nothing to
// compare and returns cleanly on text a reader can read out loud.
//
// So this asks a different question — what would this word be if it were written
// plainly? — and answers it with the fold in runeinfo. The answer is the finding:
// not "these codepoints are unusual" but "this says ignore all previous
// instructions".
//
// Nothing here is removable, for the same reason a mixed-script word is not:
// rewriting 𝐱 as x is a decision about what the author meant, and in a document
// with actual mathematics in it the answer is that they meant 𝐱. See
// docs/decisions/lossless-only.md.
type Styled struct{}

func (Styled) Name() string { return "styled" }

func (Styled) Applies(f detect.Format) bool { return true }

// minStyled is how much of a word has to be in costume before this says anything.
//
// A single mathematical letter is mathematics. Two in a row inside a word of at
// least three characters is a word someone typed in a font picker and pasted, and
// that is the thing worth reporting. Getting this boundary wrong in the generous
// direction would make the detector fire on every equation in every paper, which
// is the fastest way to teach someone to ignore a tool.
const (
	minStyled = 2
	minWord   = 3
)

func (d Styled) Detect(src *detect.Source) (finding.Set, error) {
	var out finding.Set
	for _, region := range src.Regions {
		out = append(out, d.scan(region)...)
	}
	return out, nil
}

func (d Styled) scan(r detect.Region) finding.Set {
	var out finding.Set
	for _, w := range styledWords(r.Text) {
		if utf8.RuneCountInString(w.text) < minWord || countStyled(w.text) < minStyled {
			continue
		}
		if hasCJK(w.text) {
			// Fullwidth forms are how CJK text is correctly typeset — 「！」 is the
			// exclamation mark of that writing system, not a Latin one in
			// disguise. Folding it to "!" produces a "reading" that is an
			// artefact of this code rather than a fact about the document.
			continue
		}
		reading, style, ok := runeinfo.StyledWord(w.text)
		if !ok {
			continue
		}

		span := r.Span(w.at, len(w.text))
		out = append(out, finding.New(d.Name(), KindStyledWord, finding.Confusable,
			finding.Concern, span,
			fmt.Sprintf("%q is %s letters — it reads as %q", w.text, style, reading),
			"Written in one of Unicode's alternate alphabets. It reads as ordinary text and "+
				"matches nothing: not a search, not a filter, not a comparison against the "+
				"word it appears to be. That gap between what it reads as and what it equals "+
				"is the entire reason to spell a word this way.").
			WithDetail(finding.NewRunes([]rune(w.text), styledNames(w.text))).
			Irremovable("Not rewritten automatically: whether these letters were meant to be plain ASCII is a judgment only you can make — in a document with mathematics in it, they were not."))
	}
	return out
}

// countStyled counts the characters in costume — but only those that read as a
// letter or a digit.
//
// The restriction is what keeps this off ordinary CJK text. Fullwidth punctuation
// folds to ASCII punctuation, so a Chinese sentence ending in "！" contains a
// styled character by the letter of the definition and nothing worth saying by any
// other measure. A word is only being disguised if the disguise is over its
// letters.
func countStyled(s string) int {
	n := 0
	for _, r := range s {
		plain, _, ok := runeinfo.Styled(r)
		if !ok {
			continue
		}
		if unicode.IsLetter(plain) || unicode.IsDigit(plain) {
			n++
		}
	}
	return n
}

// hasCJK reports whether a word contains characters from a writing system whose
// own typography uses the fullwidth forms.
func hasCJK(s string) bool {
	for _, r := range s {
		if unicode.Is(unicode.Han, r) || unicode.Is(unicode.Hiragana, r) ||
			unicode.Is(unicode.Katakana, r) || unicode.Is(unicode.Hangul, r) {
			return true
		}
	}
	return false
}

func styledNames(s string) []string {
	out := make([]string, 0, len(s))
	for _, r := range s {
		if plain, style, ok := runeinfo.Styled(r); ok {
			out = append(out, fmt.Sprintf("U+%04X %s %q", r, style, plain))
			continue
		}
		out = append(out, runeinfo.Label(r))
	}
	return out
}

// styledWords splits text into candidate words.
//
// Separate from words() in script.go rather than shared, because the two are
// looking through different windows. words() groups letters, and half the
// characters this detector cares about are not letters: U+24B6 CIRCLED LATIN
// CAPITAL LETTER A is a symbol by general category, as are the squared and
// negative-circled forms. A tokenizer built on IsLetter would drop exactly the
// ones that need catching.
func styledWords(s string) []word {
	var out []word
	start := -1
	for i, r := range s {
		if isWordish(r) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			out = append(out, word{at: start, text: s[start:i]})
			start = -1
		}
	}
	if start >= 0 {
		out = append(out, word{at: start, text: s[start:]})
	}
	return out
}

func isWordish(r rune) bool {
	if unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.Is(unicode.Mn, r) {
		return true
	}
	_, _, styled := runeinfo.Styled(r)
	return styled
}
