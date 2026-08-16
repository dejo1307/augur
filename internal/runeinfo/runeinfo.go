// Package runeinfo answers three questions about a codepoint: is it suspicious,
// what is it called, and how do you show something invisible on a screen.
//
// It carries its own name table rather than pulling in golang.org/x/text, because
// the set of codepoints augur has anything to say about is small and closed.
// Everything outside that set gets an honest fallback — its script and its
// codepoint — instead of a name looked up from a megabyte of tables.
package runeinfo

import (
	"fmt"
	"unicode"
)

// Class is what kind of suspicious a codepoint is. Normal means "nothing to say".
type Class int

const (
	Normal Class = iota
	// ZeroWidth renders as nothing and joins nothing. The workhorse of text
	// smuggling.
	ZeroWidth
	// TagChar is the Unicode Tag block, U+E0000-E007F: a full invisible mirror of
	// ASCII, which is why it is the most convenient way to hide a sentence.
	TagChar
	// VariationSelector selects an alternate glyph for the preceding character.
	// 256 of them, so a chain of them carries arbitrary bytes.
	VariationSelector
	// PrivateUse has no assigned meaning, so whatever it means was agreed
	// somewhere other than the Unicode standard.
	PrivateUse
	// BidiControl changes reading direction and can make source read differently
	// than it runs.
	BidiControl
	// ExoticSpace is whitespace that is not U+0020.
	ExoticSpace
	// LineSep separates lines or paragraphs without being \n.
	LineSep
	// Deprecated is a formatting character Unicode itself withdrew.
	Deprecated
	// Combining is an invisible combining mark used to break up text without
	// changing how it looks.
	Combining
)

func (c Class) String() string {
	switch c {
	case ZeroWidth:
		return "zero-width"
	case TagChar:
		return "tag character"
	case VariationSelector:
		return "variation selector"
	case PrivateUse:
		return "private use"
	case BidiControl:
		return "bidi control"
	case ExoticSpace:
		return "exotic space"
	case LineSep:
		return "line separator"
	case Deprecated:
		return "deprecated format"
	case Combining:
		return "combining mark"
	default:
		return "normal"
	}
}

// Hidden reports whether a class belongs to a *smuggling run* — a stretch of
// codepoints that might together encode a message.
//
// Deliberately narrower than Invisible: direction controls are invisible too, but
// they are not part of any encoding scheme, and folding them into a run would both
// corrupt the decode and let two detectors claim the same bytes.
func (c Class) Hidden() bool {
	switch c {
	case ZeroWidth, TagChar, VariationSelector, PrivateUse, Deprecated, Combining:
		return true
	}
	return false
}

// Invisible reports whether a codepoint occupies no visible space on screen.
//
// The wider question, and the one that matters when deciding what "the end of the
// line" means: a line ending in a space followed by a direction control has
// trailing whitespace, even though something sits between the space and the
// newline. Getting this wrong means removing the control exposes whitespace the
// same clean pass already walked past, so the file needs a second pass to settle.
func (c Class) Invisible() bool {
	return c.Hidden() || c == BidiControl
}

// names covers every codepoint this package classifies as anything but Normal,
// excluding the block ranges handled arithmetically in Classify.
var names = map[rune]string{
	0x00AD: "SOFT HYPHEN",
	0x034F: "COMBINING GRAPHEME JOINER",
	0x061C: "ARABIC LETTER MARK",
	0x115F: "HANGUL CHOSEONG FILLER",
	0x1160: "HANGUL JUNGSEONG FILLER",
	0x17B4: "KHMER VOWEL INHERENT AQ",
	0x17B5: "KHMER VOWEL INHERENT AA",
	0x180E: "MONGOLIAN VOWEL SEPARATOR",
	0x200B: "ZERO WIDTH SPACE",
	0x200C: "ZERO WIDTH NON-JOINER",
	0x200D: "ZERO WIDTH JOINER",
	0x200E: "LEFT-TO-RIGHT MARK",
	0x200F: "RIGHT-TO-LEFT MARK",
	0x202A: "LEFT-TO-RIGHT EMBEDDING",
	0x202B: "RIGHT-TO-LEFT EMBEDDING",
	0x202C: "POP DIRECTIONAL FORMATTING",
	0x202D: "LEFT-TO-RIGHT OVERRIDE",
	0x202E: "RIGHT-TO-LEFT OVERRIDE",
	0x2060: "WORD JOINER",
	0x2061: "FUNCTION APPLICATION",
	0x2062: "INVISIBLE TIMES",
	0x2063: "INVISIBLE SEPARATOR",
	0x2064: "INVISIBLE PLUS",
	0x2066: "LEFT-TO-RIGHT ISOLATE",
	0x2067: "RIGHT-TO-LEFT ISOLATE",
	0x2068: "FIRST STRONG ISOLATE",
	0x2069: "POP DIRECTIONAL ISOLATE",
	0x206A: "INHIBIT SYMMETRIC SWAPPING",
	0x206B: "ACTIVATE SYMMETRIC SWAPPING",
	0x206C: "INHIBIT ARABIC FORM SHAPING",
	0x206D: "ACTIVATE ARABIC FORM SHAPING",
	0x206E: "NATIONAL DIGIT SHAPES",
	0x206F: "NOMINAL DIGIT SHAPES",
	0x3164: "HANGUL FILLER",
	0xFEFF: "ZERO WIDTH NO-BREAK SPACE (BOM)",
	0xFFA0: "HALFWIDTH HANGUL FILLER",

	0x0009: "CHARACTER TABULATION",
	0x00A0: "NO-BREAK SPACE",
	0x1680: "OGHAM SPACE MARK",
	0x2000: "EN QUAD",
	0x2001: "EM QUAD",
	0x2002: "EN SPACE",
	0x2003: "EM SPACE",
	0x2004: "THREE-PER-EM SPACE",
	0x2005: "FOUR-PER-EM SPACE",
	0x2006: "SIX-PER-EM SPACE",
	0x2007: "FIGURE SPACE",
	0x2008: "PUNCTUATION SPACE",
	0x2009: "THIN SPACE",
	0x200A: "HAIR SPACE",
	0x202F: "NARROW NO-BREAK SPACE",
	0x205F: "MEDIUM MATHEMATICAL SPACE",
	0x3000: "IDEOGRAPHIC SPACE",
	0x2028: "LINE SEPARATOR",
	0x2029: "PARAGRAPH SEPARATOR",
}

// Classify says what kind of suspicious a codepoint is.
func Classify(r rune) Class {
	switch {
	case r >= 0xE0000 && r <= 0xE007F:
		return TagChar
	case r >= 0xFE00 && r <= 0xFE0F, r >= 0xE0100 && r <= 0xE01EF:
		return VariationSelector
	case r >= 0xE000 && r <= 0xF8FF, // BMP private use
		r >= 0xF0000 && r <= 0xFFFFD,   // plane 15
		r >= 0x100000 && r <= 0x10FFFD: // plane 16
		return PrivateUse
	}

	switch r {
	case 0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x180E, 0x00AD,
		0x115F, 0x1160, 0x3164, 0xFFA0, 0x17B4, 0x17B5,
		0x2061, 0x2062, 0x2063, 0x2064:
		return ZeroWidth
	case 0x034F:
		return Combining
	case 0x200E, 0x200F, 0x061C, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
		0x2066, 0x2067, 0x2068, 0x2069:
		return BidiControl
	case 0x2028, 0x2029:
		return LineSep
	case 0x206A, 0x206B, 0x206C, 0x206D, 0x206E, 0x206F:
		return Deprecated
	case 0x00A0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005,
		0x2006, 0x2007, 0x2008, 0x2009, 0x200A, 0x202F, 0x205F, 0x3000:
		return ExoticSpace
	}
	return Normal
}

// Name returns what Unicode calls the codepoint, for the codepoints this package
// knows. For anything else it returns a truthful description built from what the
// standard library does know — the script and the codepoint — rather than
// inventing a name or returning an empty string.
func Name(r rune) string {
	if n, ok := names[r]; ok {
		return n
	}
	switch Classify(r) {
	case TagChar:
		// The block mirrors ASCII exactly, which is the whole reason it is used.
		if plain := r - 0xE0000; plain >= 0x20 && plain <= 0x7E {
			return fmt.Sprintf("TAG %q", plain)
		}
		return "TAG CHARACTER"
	case VariationSelector:
		if r <= 0xFE0F {
			return fmt.Sprintf("VARIATION SELECTOR-%d", r-0xFE00+1)
		}
		return fmt.Sprintf("VARIATION SELECTOR-%d", r-0xE0100+17)
	case PrivateUse:
		return "PRIVATE USE CHARACTER"
	}
	if s := ScriptName(r); s != "" {
		return fmt.Sprintf("%s letter", s)
	}
	return "UNNAMED"
}

// Label renders a codepoint the way a person reads it out: "U+200B ZERO WIDTH SPACE".
func Label(r rune) string {
	return fmt.Sprintf("U+%04X %s", r, Name(r))
}

// Display renders a codepoint so it can be seen on a screen. Invisible characters
// come back as a bracketed mnemonic, because the one thing that must not happen in
// a tool for looking at hidden characters is for them to render as nothing.
func Display(r rune) string {
	if m, ok := mnemonics[r]; ok {
		return "⟨" + m + "⟩"
	}
	switch c := Classify(r); c {
	case TagChar:
		if plain := r - 0xE0000; plain >= 0x20 && plain <= 0x7E {
			return fmt.Sprintf("⟨TAG:%c⟩", plain)
		}
		return fmt.Sprintf("⟨TAG:%04X⟩", r)
	case VariationSelector:
		return fmt.Sprintf("⟨VS%d⟩", vsIndex(r))
	case PrivateUse:
		return fmt.Sprintf("⟨PUA:%04X⟩", r)
	case Normal:
		return string(r)
	default:
		return fmt.Sprintf("⟨%04X⟩", r)
	}
}

// vsIndex maps a variation selector to its 1-based index, which is also the byte
// value it carries in the selector smuggling scheme (offset by one).
func vsIndex(r rune) int {
	if r >= 0xFE00 && r <= 0xFE0F {
		return int(r-0xFE00) + 1
	}
	return int(r-0xE0100) + 17
}

var mnemonics = map[rune]string{
	0x200B: "ZWSP", 0x200C: "ZWNJ", 0x200D: "ZWJ", 0x2060: "WJ",
	0xFEFF: "BOM", 0x00AD: "SHY", 0x180E: "MVS", 0x034F: "CGJ",
	0x200E: "LRM", 0x200F: "RLM", 0x061C: "ALM",
	0x202A: "LRE", 0x202B: "RLE", 0x202C: "PDF", 0x202D: "LRO", 0x202E: "RLO",
	0x2066: "LRI", 0x2067: "RLI", 0x2068: "FSI", 0x2069: "PDI",
	0x00A0: "NBSP", 0x202F: "NNBSP", 0x2007: "FIGSP", 0x2009: "THINSP",
	0x2003: "EMSP", 0x2002: "ENSP", 0x3000: "IDSP", 0x205F: "MMSP",
	0x2028: "LS", 0x2029: "PS", 0x3164: "HFILL", 0x115F: "HCF", 0x1160: "HJF",
	0x2061: "FA", 0x2062: "ITIMES", 0x2063: "ISEP", 0x2064: "IPLUS",
}

// scripts are the ones that matter for mixed-script detection: the alphabets whose
// letters are visually interchangeable with Latin. Checking against all of Unicode
// would flag every legitimately multilingual document.
var scripts = []struct {
	name  string
	table *unicode.RangeTable
}{
	{"Latin", unicode.Latin},
	{"Cyrillic", unicode.Cyrillic},
	{"Greek", unicode.Greek},
	{"Armenian", unicode.Armenian},
	{"Cherokee", unicode.Cherokee},
}

// ScriptName returns the confusable-relevant script a letter belongs to, or "" if
// it belongs to none of them (including for digits, punctuation and CJK, none of
// which participate in the Latin homoglyph problem).
func ScriptName(r rune) string {
	if !unicode.IsLetter(r) {
		return ""
	}
	for _, s := range scripts {
		if unicode.Is(s.table, r) {
			return s.name
		}
	}
	return ""
}
