package runeinfo

// Latin lookalikes, for the whole-word case that mixed-script detection cannot see.
//
// The mixed-script rule catches "аpple" — one Cyrillic letter inside an otherwise
// Latin word — without any table at all, and that is the right way to do it. It
// cannot catch "раураӏ", where every letter is Cyrillic: the word is
// single-script, perfectly well formed, and identical on screen to a Latin word it
// is not. Nothing about any individual character is wrong. What is wrong is the
// pair.
//
// Seeing that needs a table, so this is one — deliberately the smallest table that
// answers the question rather than a general confusables database:
//
//   - Two scripts, Cyrillic and Greek. They are where whole-word substitution
//     actually happens, because they are the only alphabets carrying enough
//     Latin-identical letters to spell an English word from end to end.
//   - Only letters that are *indistinguishable* from their Latin counterpart in an
//     ordinary upright font, not merely similar. Cyrillic "к" and Latin "k" are
//     similar and are not here; a table built on resemblance produces confident
//     wrong readings, and a wrong reading is worse than no reading at all.
//
// The strictness has a visible consequence and it is the intended one: Greek
// lower case contributes six letters, so an all-lowercase-Greek word will almost
// never satisfy the whole-word rule. That is the correct answer. Greek lower case
// does not actually look like Latin lower case, and a check that claimed otherwise
// would spend its accuracy on words nobody is being fooled by.
//
// Curated, not generated, and stable for that reason: these letters will not stop
// looking like each other in a future Unicode release, which is the thing a
// generated confusables table has to be regenerated for.
var latinLookalikes = map[rune]rune{
	// Cyrillic, lower case.
	'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
	'ѕ': 's', 'і': 'i', 'ј': 'j', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w', 'ӏ': 'l',

	// Cyrillic, upper case.
	'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O',
	'Р': 'P', 'С': 'C', 'Т': 'T', 'У': 'Y', 'Х': 'X', 'Ѕ': 'S', 'І': 'I',
	'Ј': 'J', 'Ԁ': 'D', 'Ԛ': 'Q', 'Ԝ': 'W',

	// Greek, lower case. Short, and see the note above.
	'ο': 'o', 'ν': 'v', 'ρ': 'p', 'χ': 'x', 'ϲ': 'c', 'ϳ': 'j',

	// Greek, upper case.
	'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I', 'Κ': 'K',
	'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
	'Ϲ': 'C', 'Ϳ': 'J',
}

// LatinLookalike returns the Latin character this one is visually mistaken for,
// and whether there is one at all.
func LatinLookalike(r rune) (rune, bool) {
	l, ok := latinLookalikes[r]
	return l, ok
}

// LatinReading spells a word out in the Latin letters it appears to be written in,
// and reports false if any character has no Latin lookalike.
//
// That "any" is what keeps this quiet on genuine Cyrillic and Greek text. Real
// vocabulary reaches a letter with no Latin twin almost immediately — "привет"
// fails on its second character — so the rule needs no guess about what language
// the document is in, which is the kind of guess that goes wrong on the one
// document where it matters.
func LatinReading(word string) (string, bool) {
	out := make([]rune, 0, len(word))
	for _, r := range word {
		l, ok := latinLookalikes[r]
		if !ok {
			return "", false
		}
		out = append(out, l)
	}
	if len(out) == 0 {
		return "", false
	}
	return string(out), true
}
