package runeinfo

// Styled letters: the ASCII alphabet wearing a costume.
//
// Unicode carries the Latin alphabet several times over — mathematical bold,
// italic, script, fraktur, double-struck, sans, monospace, fullwidth, circled,
// squared, small capitals. Every copy reads as plain English to a person and as
// something else entirely to anything comparing strings, which makes it the
// standard way to get a phrase past a filter that is looking for the phrase.
//
// The mixed-script detector cannot see any of this, and not by oversight: the
// Unicode script property of U+1D400 MATHEMATICAL BOLD CAPITAL A is Common, not
// Latin, so a word spelled entirely in mathematical bold mixes no scripts. It has
// exactly one script, and that script is "not a script".
//
// So this is a fold rather than a script comparison: what would this character be
// if it were written plainly? The answer comes from arithmetic over the blocks
// wherever possible, because the blocks are laid out in alphabetical order, and
// from a table only where Unicode broke that order.

// styleRange is one contiguous run of styled characters that maps onto a
// contiguous run of ASCII.
type styleRange struct {
	lo, hi rune   // inclusive, in the styled block
	base   rune   // the ASCII character lo corresponds to
	style  string // what to call it when reporting
}

// styleRanges is ordered by codepoint. Every entry is a straight offset: the
// blocks were allocated in A-Z then a-z order precisely so that this works.
var styleRanges = []styleRange{
	{0x1D400, 0x1D419, 'A', "mathematical bold"},
	{0x1D41A, 0x1D433, 'a', "mathematical bold"},
	{0x1D434, 0x1D44D, 'A', "mathematical italic"},
	{0x1D44E, 0x1D467, 'a', "mathematical italic"},
	{0x1D468, 0x1D481, 'A', "mathematical bold italic"},
	{0x1D482, 0x1D49B, 'a', "mathematical bold italic"},
	{0x1D49C, 0x1D4B5, 'A', "mathematical script"},
	{0x1D4B6, 0x1D4CF, 'a', "mathematical script"},
	{0x1D4D0, 0x1D4E9, 'A', "mathematical bold script"},
	{0x1D4EA, 0x1D503, 'a', "mathematical bold script"},
	{0x1D504, 0x1D51D, 'A', "fraktur"},
	{0x1D51E, 0x1D537, 'a', "fraktur"},
	{0x1D538, 0x1D551, 'A', "double-struck"},
	{0x1D552, 0x1D56B, 'a', "double-struck"},
	{0x1D56C, 0x1D585, 'A', "bold fraktur"},
	{0x1D586, 0x1D59F, 'a', "bold fraktur"},
	{0x1D5A0, 0x1D5B9, 'A', "sans-serif"},
	{0x1D5BA, 0x1D5D3, 'a', "sans-serif"},
	{0x1D5D4, 0x1D5ED, 'A', "sans-serif bold"},
	{0x1D5EE, 0x1D607, 'a', "sans-serif bold"},
	{0x1D608, 0x1D621, 'A', "sans-serif italic"},
	{0x1D622, 0x1D63B, 'a', "sans-serif italic"},
	{0x1D63C, 0x1D655, 'A', "sans-serif bold italic"},
	{0x1D656, 0x1D66F, 'a', "sans-serif bold italic"},
	{0x1D670, 0x1D689, 'A', "monospace"},
	{0x1D68A, 0x1D6A3, 'a', "monospace"},

	// Digits. Same idea, five more copies of 0-9.
	{0x1D7CE, 0x1D7D7, '0', "mathematical bold"},
	{0x1D7D8, 0x1D7E1, '0', "double-struck"},
	{0x1D7E2, 0x1D7EB, '0', "sans-serif"},
	{0x1D7EC, 0x1D7F5, '0', "sans-serif bold"},
	{0x1D7F6, 0x1D7FF, '0', "monospace"},

	// Fullwidth forms. The whole printable ASCII range, offset by one block.
	{0xFF01, 0xFF5E, '!', "fullwidth"},

	// Enclosed alphanumerics.
	{0x24B6, 0x24CF, 'A', "circled"},
	{0x24D0, 0x24E9, 'a', "circled"},
	{0x1F110, 0x1F129, 'A', "parenthesised"},
	{0x1F130, 0x1F149, 'A', "squared"},
	{0x1F150, 0x1F169, 'A', "negative circled"},
	{0x1F170, 0x1F189, 'A', "negative squared"},
}

// styleHoles are the codepoints Unicode left reserved inside the mathematical
// blocks because the character already existed in the Letterlike Symbols block.
// The reserved slot is unassigned, so text carries the older codepoint instead —
// which means arithmetic alone would miss precisely the letters that turn up in
// practice.
var styleHoles = map[rune]struct {
	ascii rune
	style string
}{
	0x210E: {'h', "mathematical italic"},
	0x212C: {'B', "mathematical script"},
	0x2130: {'E', "mathematical script"},
	0x2131: {'F', "mathematical script"},
	0x210B: {'H', "mathematical script"},
	0x2110: {'I', "mathematical script"},
	0x2112: {'L', "mathematical script"},
	0x2133: {'M', "mathematical script"},
	0x211B: {'R', "mathematical script"},
	0x212F: {'e', "mathematical script"},
	0x210A: {'g', "mathematical script"},
	0x2134: {'o', "mathematical script"},
	0x212D: {'C', "fraktur"},
	0x210C: {'H', "fraktur"},
	0x2111: {'I', "fraktur"},
	0x211C: {'R', "fraktur"},
	0x2128: {'Z', "fraktur"},
	0x2102: {'C', "double-struck"},
	0x210D: {'H', "double-struck"},
	0x2115: {'N', "double-struck"},
	0x2119: {'P', "double-struck"},
	0x211A: {'Q', "double-struck"},
	0x211D: {'R', "double-struck"},
	0x2124: {'Z', "double-struck"},
	0x2145: {'D', "double-struck italic"},
	0x2146: {'d', "double-struck italic"},
	0x2147: {'e', "double-struck italic"},
	0x2148: {'i', "double-struck italic"},
	0x2149: {'j', "double-struck italic"},

	// Small capitals and the phonetic letters used as them. These are Latin by
	// script — the mixed-script rule sees nothing wrong, correctly — and they
	// spell "ɪɢɴᴏʀᴇ ᴀʟʟ ᴘʀᴇᴠɪᴏᴜs ɪɴsᴛʀᴜᴄᴛɪᴏɴs" perfectly legibly.
	0x1D00: {'a', "small capital"},
	0x0299: {'b', "small capital"},
	0x1D04: {'c', "small capital"},
	0x1D05: {'d', "small capital"},
	0x1D07: {'e', "small capital"},
	0xA730: {'f', "small capital"},
	0x0262: {'g', "small capital"},
	0x029C: {'h', "small capital"},
	0x026A: {'i', "small capital"},
	0x1D0A: {'j', "small capital"},
	0x1D0B: {'k', "small capital"},
	0x029F: {'l', "small capital"},
	0x1D0D: {'m', "small capital"},
	0x0274: {'n', "small capital"},
	0x1D0F: {'o', "small capital"},
	0x1D18: {'p', "small capital"},
	0x0280: {'r', "small capital"},
	0xA731: {'s', "small capital"},
	0x1D1B: {'t', "small capital"},
	0x1D1C: {'u', "small capital"},
	0x1D20: {'v', "small capital"},
	0x1D21: {'w', "small capital"},
	0x028F: {'y', "small capital"},
	0x1D22: {'z', "small capital"},
}

// Styled reports what a styled character reads as in plain ASCII, and what the
// styling is called. It returns false for anything that is already plain.
func Styled(r rune) (plain rune, style string, ok bool) {
	if r < 0x80 {
		return 0, "", false // ASCII is not a costume
	}
	if h, found := styleHoles[r]; found {
		return h.ascii, h.style, true
	}
	for _, sr := range styleRanges {
		if r >= sr.lo && r <= sr.hi {
			return sr.base + (r - sr.lo), sr.style, true
		}
	}
	return 0, "", false
}

// StyledWord folds a whole word and reports what it reads as, whether any of it
// was styled, and what the styling was called.
//
// Characters with no styled form are passed through rather than rejected, so a
// word that mixes plain and styled letters — "𝗶gnore", the shape a filter bypass
// usually takes — still reads out correctly.
func StyledWord(word string) (reading, style string, styled bool) {
	out := make([]rune, 0, len(word))
	styles := map[string]bool{}
	for _, r := range word {
		if p, s, ok := Styled(r); ok {
			out = append(out, p)
			styles[s] = true
			continue
		}
		out = append(out, r)
	}
	if len(styles) == 0 {
		return "", "", false
	}
	// One name when the word is styled consistently, and an honest plural when it
	// is not — mixing three styles in one word is itself worth seeing.
	name := ""
	for s := range styles {
		if name != "" {
			return string(out), "mixed styles", true
		}
		name = s
	}
	return string(out), name, true
}
