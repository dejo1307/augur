package text

import (
	"fmt"
	"unicode/utf8"

	"github.com/dejo1307/augur/pkg/detect"
	"github.com/dejo1307/augur/pkg/finding"
)

const (
	KindBOM         = finding.Kind("byte-order-mark")
	KindInvalidUTF8 = finding.Kind("invalid-utf8")
)

// Encoding finds byte-order marks and byte sequences that are not valid UTF-8.
//
// The BOM is reported as a notice, not a problem: it is legitimate, common, and
// invisible, and the only reason to surface it is that "invisible thing at the
// start of my file" is exactly the class of question this tool exists to answer.
//
// Invalid UTF-8 is reported and never repaired. Every repair is a guess about what
// encoding the bytes were meant to be, and a wrong guess corrupts text
// irreversibly while looking like it worked.
type Encoding struct{}

func (Encoding) Name() string { return "encoding" }

func (Encoding) Applies(f detect.Format) bool { return true }

func (d Encoding) Detect(src *detect.Source) (finding.Set, error) {
	var out finding.Set
	for _, region := range src.Regions {
		out = append(out, d.bom(region)...)
		out = append(out, d.invalid(region)...)
	}
	return out, nil
}

func (d Encoding) bom(r detect.Region) finding.Set {
	// Written as an escape rather than the character itself: Go's own compiler
	// rejects a literal BOM in the middle of a source file, which is a small
	// demonstration of why this detector exists.
	const bom = "\uFEFF"
	if len(r.Text) < len(bom) || r.Text[:len(bom)] != bom {
		return nil
	}
	span := r.Span(0, len(bom))
	f := finding.New(d.Name(), KindBOM, finding.Encoding, finding.Notice, span,
		"U+FEFF BYTE ORDER MARK",
		"An invisible marker at the very start of the file declaring its encoding. Harmless "+
			"and common, but it is a real character: it breaks shebang lines, JSON parsers and "+
			"exact string comparisons against the first line.").
		WithDetail(finding.NewRunes([]rune{0xFEFF}, []string{"U+FEFF ZERO WIDTH NO-BREAK SPACE (BOM)"}))
	if span.Exact {
		return finding.Set{f.Deletable()}
	}
	return finding.Set{f.Irremovable("Found inside re-encoded text.")}
}

func (d Encoding) invalid(r detect.Region) finding.Set {
	var out finding.Set
	s := r.Text
	for i := 0; i < len(s); {
		c, size := utf8.DecodeRuneInString(s[i:])
		if c != utf8.RuneError || size > 1 {
			i += size
			continue
		}
		// A maximal run of undecodable bytes reads better than one finding per byte.
		start := i
		for i < len(s) {
			c, size := utf8.DecodeRuneInString(s[i:])
			if c != utf8.RuneError || size > 1 {
				break
			}
			i++
		}
		out = append(out, finding.New(d.Name(), KindInvalidUTF8, finding.Encoding,
			finding.Concern, r.Span(start, i-start),
			fmt.Sprintf("%d byte(s) that are not valid UTF-8", i-start),
			"These bytes do not decode as text. They may be a different encoding that was "+
				"never converted, or binary data sitting inside a text file.").
			WithDetail(finding.NewBlob(i-start, []byte(s[start:i]), "")).
			Irremovable("Not repaired: guessing which encoding these bytes were meant to be would corrupt them irreversibly if the guess were wrong."))
	}
	return out
}
