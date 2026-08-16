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

const KindMixedScript = finding.Kind("mixed-script")

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
	for _, w := range words(r.Text) {
		seen := map[string][]rune{}
		for _, c := range w.text {
			if s := runeinfo.ScriptName(c); s != "" {
				seen[s] = append(seen[s], c)
			}
		}
		if len(seen) < 2 {
			continue
		}
		scripts := make([]string, 0, len(seen))
		for s := range seen {
			scripts = append(scripts, s)
		}
		sort.Strings(scripts)

		// The odd ones out: characters from every script but the majority one.
		major := majorityScript(seen)
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

func majorityScript(seen map[string][]rune) string {
	best, bestN := "", -1
	keys := make([]string, 0, len(seen))
	for s := range seen {
		keys = append(keys, s)
	}
	sort.Strings(keys) // deterministic on ties
	for _, s := range keys {
		if n := len(seen[s]); n > bestN {
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
