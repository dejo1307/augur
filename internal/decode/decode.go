// Package decode turns a run of invisible codepoints back into what it says.
//
// This is the difference between a linter and this tool. "17 zero-width
// characters" is a fact nobody can act on. "these 17 characters say: ignore
// previous instructions" is the whole finding, and it is recoverable because every
// scheme in use is a straightforward encoding rather than encryption.
//
// Everything here is a pure function of a rune slice. The package sits in the
// analysis layer beside detect, and imports only the core vocabulary.
package decode

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Result is a successful decode.
type Result struct {
	// Scheme names how it was encoded, in words a user can look up.
	Scheme string
	// Bytes is what came out.
	Bytes []byte
	// Text is Bytes as a string, when they were valid UTF-8.
	Text string
	// Printable reports whether Text is readable. A run that decodes to valid but
	// unreadable bytes is still reported: something structured is in there, and
	// that is worth knowing even when it cannot be read.
	Printable bool
}

// scheme is one encoding augur knows how to reverse.
type scheme struct {
	name   string
	decode func([]rune) ([]byte, bool)
}

// schemes are tried in order. Order matters only for runs that could satisfy more
// than one, which the alphabets make almost impossible: tag characters, variation
// selectors and zero-width characters live in disjoint blocks.
var schemes = []scheme{
	{"Unicode tag characters (U+E0000 block)", decodeTags},
	{"variation selectors", decodeVariationSelectors},
	{"zero-width binary (ZWSP/ZWNJ)", decodeZeroWidthBinary},
	{"zero-width binary (ZWSP/ZWJ)", decodeZeroWidthBinaryJoiner},
}

// MinBytes is the shortest decode worth reporting as a message. Below this,
// coincidence is likelier than intent — two stray tag characters are not a
// sentence, and calling them one would train the user to distrust the tool.
const MinBytes = 3

// Decode tries every known scheme against a run of invisible codepoints and
// returns the first that produces something plausible.
//
// Failure is the normal case and is not an error: most runs of invisible
// characters are exactly what they look like.
func Decode(run []rune) (Result, bool) {
	if len(run) == 0 {
		return Result{}, false
	}
	for _, s := range schemes {
		raw, ok := s.decode(run)
		if !ok || len(raw) < MinBytes {
			continue
		}
		text, printable := interpret(raw)
		if !printable && !structured(raw) {
			// Decoded, but into noise. A scheme that produces arbitrary bytes
			// from arbitrary input would otherwise "succeed" on everything.
			continue
		}
		return Result{Scheme: s.name, Bytes: raw, Text: text, Printable: printable}, true
	}
	return Result{}, false
}

// interpret renders decoded bytes as text and says whether a human could read them.
func interpret(raw []byte) (string, bool) {
	if !utf8.Valid(raw) {
		return "", false
	}
	s := string(raw)
	printable := 0
	total := 0
	for _, r := range s {
		total++
		if unicode.IsPrint(r) || r == '\n' || r == '\t' {
			printable++
		}
	}
	if total == 0 {
		return s, false
	}
	// Nine in ten readable is the line. A decoded sentence carrying one stray
	// control byte is still a sentence; a byte soup that happens to hold some
	// ASCII is not.
	return s, printable*10 >= total*9
}

// structured reports whether unreadable bytes nonetheless look deliberate — a
// recognisable file header smuggled into a text file is a finding even though it
// will never render as a sentence.
func structured(raw []byte) bool {
	for _, magic := range []string{"PK\x03\x04", "\x89PNG", "\xFF\xD8\xFF", "%PDF", "GIF8", "\x7FELF"} {
		if strings.HasPrefix(string(raw), magic) {
			return true
		}
	}
	return false
}

// decodeTags reverses the Unicode Tag block, which mirrors ASCII exactly: U+E0041
// is "A". The block was withdrawn from its original purpose and left invisible,
// which is why it became the most convenient way to hide a sentence in plain text.
func decodeTags(run []rune) ([]byte, bool) {
	out := make([]byte, 0, len(run))
	for _, r := range run {
		if r < 0xE0000 || r > 0xE007F {
			return nil, false
		}
		b := byte(r - 0xE0000)
		if b == 0x01 {
			continue // the language-tag introducer, if present, is framing
		}
		out = append(out, b)
	}
	return out, len(out) > 0
}

// decodeVariationSelectors reverses the selector scheme: byte b is carried as
// U+FE00+b for b < 16 and U+E0100+(b-16) for the rest, giving all 256 values. The
// selectors attach invisibly to a preceding character, so a single emoji can carry
// a paragraph.
func decodeVariationSelectors(run []rune) ([]byte, bool) {
	out := make([]byte, 0, len(run))
	for _, r := range run {
		switch {
		case r >= 0xFE00 && r <= 0xFE0F:
			out = append(out, byte(r-0xFE00))
		case r >= 0xE0100 && r <= 0xE01EF:
			out = append(out, byte(r-0xE0100+16))
		default:
			return nil, false
		}
	}
	return out, len(out) > 0
}

func decodeZeroWidthBinary(run []rune) ([]byte, bool) {
	return decodeBits(run, 0x200B, 0x200C)
}

func decodeZeroWidthBinaryJoiner(run []rune) ([]byte, bool) {
	return decodeBits(run, 0x200B, 0x200D)
}

// decodeBits reverses a two-symbol binary encoding, eight bits to the byte,
// most-significant first. Ignores a word joiner used as a frame marker, which
// several published implementations insert.
func decodeBits(run []rune, zero, one rune) ([]byte, bool) {
	bits := make([]byte, 0, len(run))
	for _, r := range run {
		switch r {
		case zero:
			bits = append(bits, 0)
		case one:
			bits = append(bits, 1)
		case 0x2060, 0xFEFF:
			continue // framing, not payload
		default:
			return nil, false
		}
	}
	if len(bits) == 0 || len(bits)%8 != 0 {
		return nil, false
	}
	out := make([]byte, 0, len(bits)/8)
	for i := 0; i < len(bits); i += 8 {
		var b byte
		for j := 0; j < 8; j++ {
			b = b<<1 | bits[i+j]
		}
		out = append(out, b)
	}
	return out, true
}

// Schemes lists the encodings augur can reverse, for the blind-spots panel.
// Naming what it can do is half of naming what it cannot.
func Schemes() []string {
	out := make([]string, len(schemes))
	for i, s := range schemes {
		out[i] = s.name
	}
	return out
}
