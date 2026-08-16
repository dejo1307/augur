// Package text holds the detectors that read a file as characters rather than as a
// container. Each one covers a single family and knows nothing about the engine,
// the session or the viewer. See docs/decisions/detector-contract.md.
package text

import (
	"fmt"
	"unicode/utf8"

	"github.com/dejo1307/augur/internal/decode"
	"github.com/dejo1307/augur/internal/runeinfo"
	"github.com/dejo1307/augur/pkg/detect"
	"github.com/dejo1307/augur/pkg/finding"
)

// Kinds emitted by this detector.
const (
	KindHiddenRun = finding.Kind("hidden-run")
	KindSmuggled  = finding.Kind("smuggled-message")
)

// Hidden finds runs of codepoints that render as nothing, and reports what they
// say when they say anything.
//
// Runs rather than individual characters, and one detector rather than two, both
// for the same reason: a decoded message is a property of a whole run, so a design
// that reported characters individually would have to reassemble them somewhere
// else and coordinate two detectors over one set of bytes. Grouping first makes
// the message the primary finding and the raw characters the fallback.
type Hidden struct{}

func (Hidden) Name() string { return "hidden" }

func (Hidden) Applies(f detect.Format) bool { return true } // any file can hold text regions

func (d Hidden) Detect(src *detect.Source) (finding.Set, error) {
	var out finding.Set
	for _, region := range src.Regions {
		out = append(out, d.scanRegion(region)...)
	}
	return out, nil
}

func (d Hidden) scanRegion(r detect.Region) finding.Set {
	var out finding.Set
	for _, run := range hiddenRuns(r.Text) {
		out = append(out, d.report(r, run))
	}
	return out
}

// run is a maximal stretch of consecutive hidden codepoints.
type run struct {
	at     int // byte offset within the region's text
	length int // byte length
	runes  []rune
}

func hiddenRuns(s string) []run {
	var runs []run
	var cur *run
	for i, r := range s {
		// A U+FEFF at the very start is the byte-order mark, and the encoding
		// detector owns it. Without this the two detectors would both claim the
		// same bytes, and their removals would be overlapping edits.
		if i == 0 && r == 0xFEFF {
			continue
		}
		if runeinfo.Classify(r).Hidden() {
			size := utf8.RuneLen(r)
			if cur == nil {
				runs = append(runs, run{at: i})
				cur = &runs[len(runs)-1]
			}
			cur.length += size
			cur.runes = append(cur.runes, r)
			continue
		}
		cur = nil
	}
	return runs
}

func (d Hidden) report(r detect.Region, run run) finding.Finding {
	span := r.Span(run.at, run.length)

	if res, ok := decode.Decode(run.runes); ok {
		label := fmt.Sprintf("hidden message, %d characters", len(run.runes))
		why := "These invisible characters are not decoration: they decode cleanly to " +
			"content that was placed here to be read by something other than you — " +
			"commonly a model reading the file, or a fingerprint identifying who this copy went to."
		if !res.Printable {
			label = fmt.Sprintf("hidden data, %d characters", len(run.runes))
			why = "These invisible characters decode to structured binary rather than " +
				"readable text, which means something was deliberately packed into them."
		}
		f := finding.New(d.Name(), KindSmuggled, finding.Steganographic, finding.Alarm,
			span, label, why).
			WithDetail(finding.NewDecoded(res.Scheme, res.Text, res.Bytes, res.Printable))
		if span.Exact {
			return f.Deletable()
		}
		return f.Irremovable("Found inside re-encoded text, so it can only be removed by dropping the block that contains it.")
	}

	cps := make([]rune, len(run.runes))
	copy(cps, run.runes)
	names := make([]string, len(run.runes))
	for i, r := range run.runes {
		names[i] = runeinfo.Label(r)
	}

	sev := finding.Concern
	if len(run.runes) == 1 {
		// A single stray invisible character is usually a copy-paste artefact.
		sev = finding.Notice
	}

	label := fmt.Sprintf("%d invisible character(s): %s", len(run.runes), runeinfo.Name(run.runes[0]))
	if len(run.runes) == 1 {
		label = runeinfo.Label(run.runes[0])
	}
	f := finding.New(d.Name(), KindHiddenRun, finding.Invisible, sev, span, label,
		"Renders as nothing, so it survives being read, copied and pasted without anyone noticing. "+
			"It does not decode to a message under any scheme augur knows.").
		WithDetail(finding.Runes{
			Detail: "runes", Codepoints: cps, Names: names,
			Context: contextAround(r.Text, run.at, run.length),
		})
	if span.Exact {
		return f.Deletable()
	}
	return f.Irremovable("Found inside re-encoded text, so it can only be removed by dropping the block that contains it.")
}

// contextAround returns the text surrounding a span with the span still in it, so
// a renderer can show a finding in place. Bounded, and cut on rune boundaries.
func contextAround(s string, at, length int) string {
	const pad = 48
	start := at - pad
	if start < 0 {
		start = 0
	}
	for start < at && !utf8.RuneStart(s[start]) {
		start++
	}
	end := at + length + pad
	if end > len(s) {
		end = len(s)
	}
	for end < len(s) && !utf8.RuneStart(s[end]) {
		end++
	}
	return s[start:end]
}
