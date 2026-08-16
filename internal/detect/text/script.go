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

const (
	KindMixedScript = finding.Kind("mixed-script")
	KindWholeScript = finding.Kind("whole-script-confusable")
)

// Script finds words that mix alphabets — a Latin word with a Cyrillic "а" in it,
// which renders identically and compares unequal.
//
// This is mixed-script detection from Unicode UTS #39, and it is deliberately not
// a confusables table. A table maps six thousand characters to their lookalikes
// and would have to be regenerated with every Unicode release; the mixed-script
// rule needs only the standard library's script tables, and it catches the attack
// that actually happens. A homoglyph is only useful to an attacker inside a word
// that is otherwise normal, and that is exactly what this sees.
//
// Nothing here is removable. The fix for "аpple" is to replace the Cyrillic а with
// a Latin a — but the tool cannot know that the word was meant to be Latin rather
// than the reverse, and guessing would silently rewrite meaning. See
// docs/decisions/lossless-only.md.
type Script struct{}

func (Script) Name() string { return "script" }

func (Script) Applies(f detect.Format) bool { return true }

func (d Script) Detect(src *detect.Source) (finding.Set, error) {
	var out finding.Set
	for _, region := range src.Regions {
		out = append(out, d.scan(region)...)
	}
	return out, nil
}

func (d Script) scan(r detect.Region) finding.Set {
	var out finding.Set
	host := dominantScript(r.Text)
	for _, w := range words(r.Text) {
		seen := map[string][]rune{}
		for _, c := range w.text {
			if s := runeinfo.ScriptName(c); s != "" {
				seen[s] = append(seen[s], c)
			}
		}
		if len(seen) == 1 {
			if f, ok := d.wholeScript(r, w, seen, host); ok {
				out = append(out, f)
			}
			continue
		}
		if len(seen) == 0 {
			continue
		}
		scripts := make([]string, 0, len(seen))
		for s := range seen {
			scripts = append(scripts, s)
		}
		sort.Strings(scripts)

		// The odd ones out: characters from every script but the majority one.
		counts := make(map[string]int, len(seen))
		for s, rs := range seen {
			counts[s] = len(rs)
		}
		major := majorityScript(counts)
		var odd []rune
		var names []string
		for s, rs := range seen {
			if s == major {
				continue
			}
			odd = append(odd, rs...)
			for _, c := range rs {
				names = append(names, runeinfo.Label(c))
			}
		}

		span := r.Span(w.at, len(w.text))
		out = append(out, finding.New(d.Name(), KindMixedScript, finding.Confusable,
			finding.Concern, span,
			fmt.Sprintf("%q mixes %s", w.text, strings.Join(scripts, " and ")),
			fmt.Sprintf("This word is written in more than one alphabet. The %s characters look "+
				"identical to their %s lookalikes but are different codepoints, so the word will "+
				"not match a search, a comparison, or an allow-list entry that spells it the "+
				"obvious way.", strings.Join(without(scripts, major), " and "), major)).
			WithDetail(finding.NewRunes(odd, names)).
			Irremovable("Not removed automatically: which alphabet the word was meant to be written in is a judgment only you can make."))
	}
	return out
}

// wholeScript reports a word written entirely in one non-Latin alphabet whose
// every letter has a Latin twin — "раураӏ" — inside a document that is otherwise
// Latin.
//
// This is the half of UTS #39 that mixed-script detection cannot reach. "аpple"
// is caught by noticing two alphabets in one word and needs no table; "раураӏ" is
// one alphabet, correctly spelled, and wrong only in relation to the document
// around it and to a Latin word it is not. Both facts are needed, and both are
// available here: the word, and the text it sits in.
//
// The host-script condition is what keeps this quiet in the documents where it
// would otherwise be loud. In a Russian document, Cyrillic words written in
// Cyrillic are the entire text and none of them are a substitution for anything.
func (d Script) wholeScript(r detect.Region, w word, seen map[string][]rune, host string) (finding.Finding, bool) {
	var script string
	for s := range seen {
		script = s
	}
	if script == "Latin" || host != "Latin" {
		return finding.Finding{}, false
	}
	reading, ok := runeinfo.LatinReading(w.text)
	if !ok {
		return finding.Finding{}, false
	}

	names := make([]string, 0, len(w.text))
	cps := make([]rune, 0, len(w.text))
	for _, c := range w.text {
		cps = append(cps, c)
		names = append(names, runeinfo.Label(c))
	}

	span := r.Span(w.at, len(w.text))
	return finding.New(d.Name(), KindWholeScript, finding.Confusable, finding.Alarm, span,
		fmt.Sprintf("%q is entirely %s — it reads as %q", w.text, script, reading),
		fmt.Sprintf("Every letter in this word is %s, and every one of them is indistinguishable "+
			"from the Latin letter it stands in for. In a document written in Latin script "+
			"there is nothing to see and nothing to search for: it will not match %q anywhere, "+
			"and it is not a typo — a word does not end up in another alphabet by accident.",
			script, reading)).
		WithDetail(finding.NewRunes(cps, names)).
		Irremovable("Not rewritten automatically: substituting the Latin spelling would change every character in the word, and only you can say which spelling was meant."), true
}

// dominantScript names the alphabet a stretch of text is mostly written in, which
// is the context a single word cannot supply about itself.
func dominantScript(s string) string {
	counts := map[string]int{}
	for _, r := range s {
		if name := runeinfo.ScriptName(r); name != "" {
			counts[name]++
		}
	}
	return majorityScript(counts)
}

func majorityScript(counts map[string]int) string {
	best, bestN := "", -1
	keys := make([]string, 0, len(counts))
	for s := range counts {
		keys = append(keys, s)
	}
	sort.Strings(keys) // deterministic on ties
	for _, s := range keys {
		if n := counts[s]; n > bestN {
			best, bestN = s, n
		}
	}
	return best
}

func without(all []string, drop string) []string {
	out := make([]string, 0, len(all))
	for _, s := range all {
		if s != drop {
			out = append(out, s)
		}
	}
	return out
}

type word struct {
	at   int
	text string
}

// words splits text into maximal runs of letters and combining marks. Digits,
// punctuation and whitespace are separators: a mixed-script finding is about one
// word, and treating "user-имя" as a single token would report a hyphenated
// bilingual phrase as an attack.
func words(s string) []word {
	var out []word
	start := -1
	for i, r := range s {
		if unicode.IsLetter(r) || unicode.Is(unicode.Mn, r) {
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
	// Single characters cannot mix scripts with themselves.
	filtered := out[:0]
	for _, w := range out {
		if utf8.RuneCountInString(w.text) > 1 {
			filtered = append(filtered, w)
		}
	}
	return filtered
}
