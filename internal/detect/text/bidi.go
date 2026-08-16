package text

import (
	"unicode/utf8"

	"github.com/dejo1307/augur/internal/runeinfo"
	"github.com/dejo1307/augur/pkg/detect"
	"github.com/dejo1307/augur/pkg/finding"
)

const KindBidiControl = finding.Kind("bidi-control")

// Bidi finds direction-control codepoints.
//
// These are the Trojan Source characters (CVE-2021-42574): they reorder how text
// is displayed without changing the bytes, so a reviewer reading a diff and a
// compiler reading the file can disagree about what the code says. Legitimate in
// genuinely bidirectional text, which is why the finding explains rather than
// accuses — but in a file that is otherwise entirely left-to-right, an override is
// worth a hard look.
type Bidi struct{}

func (Bidi) Name() string { return "bidi" }

func (Bidi) Applies(f detect.Format) bool { return true }

func (d Bidi) Detect(src *detect.Source) (finding.Set, error) {
	var out finding.Set
	for _, region := range src.Regions {
		for i, r := range region.Text {
			if runeinfo.Classify(r) != runeinfo.BidiControl {
				continue
			}
			span := region.Span(i, utf8.RuneLen(r))
			f := finding.New(d.Name(), KindBidiControl, finding.Bidi, severityOf(r), span,
				runeinfo.Label(r),
				"Changes the direction text is displayed in without changing the bytes, so what "+
					"you read here and what a compiler or interpreter reads can differ.").
				WithDetail(finding.NewRunes([]rune{r}, []string{runeinfo.Label(r)}))
			if span.Exact {
				f = f.Deletable()
			} else {
				f = f.Irremovable("Found inside re-encoded text.")
			}
			out = append(out, f)
		}
	}
	return out, nil
}

// severityOf separates the two halves of the bidi block. Marks and isolates appear
// constantly in ordinary multilingual text; the embedding and override characters
// are the ones the Trojan Source attack actually needs.
func severityOf(r rune) finding.Severity {
	switch r {
	case 0x202A, 0x202B, 0x202D, 0x202E, 0x202C:
		return finding.Alarm
	default:
		return finding.Notice
	}
}
