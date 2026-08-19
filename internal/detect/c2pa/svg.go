package c2pa

import (
	"bytes"
	"fmt"

	"github.com/dejo1307/augur/pkg/detect"
	"github.com/dejo1307/augur/pkg/finding"
)

// Kinds emitted by the SVG detector. They match the image detector's, because a
// Content Credential in an SVG is the same fact as one in a PNG and a report that
// called them different things would be filtering on the carrier rather than on
// what was found.
const (
	KindManifest = finding.Kind("c2pa-manifest")
	KindBroken   = finding.Kind("c2pa-binding-mismatch")
)

// SVG finds Content Credentials in SVG documents.
//
// It is a text detector rather than an image one, and that is a fact about SVG
// rather than a convenience: an SVG is XML, so augur already reads it as text, and
// a credential in one is base64 inside an element. Which also means removing it
// needs no container rewrite — the bytes of the element are the bytes to delete.
//
// This carrier is worth having because SVG is one of the formats generators are
// signing today. A file augur reads as text and reports as clean, while carrying
// a signed record of the model that produced it, would be a hole in the middle of
// what this tool is for.
type SVG struct{}

func (SVG) Name() string { return "c2pa-svg" }

func (SVG) Applies(f detect.Format) bool { return f == detect.Text }

func (d SVG) Detect(src *detect.Source) (finding.Set, error) {
	// An SVG sniffs as text like any other XML, so the detector confirms the
	// document before looking for anything in it.
	if !bytes.Contains(src.Bytes, []byte("<svg")) {
		return nil, nil
	}
	m, ok := InSVG(src.Bytes)
	if !ok {
		return nil, nil
	}

	span := finding.Span{Offset: m.Offset, Length: m.Length, Exact: true}
	report := Read(m.Store, src.Bytes, m.Payload)

	label := fmt.Sprintf("C2PA Content Credential in <c2pa:manifest> (%d bytes)", len(m.Store))
	severity := finding.Notice
	if summary := report.Summary(); summary != "" {
		label += " — " + summary
	}
	if report.Err != nil {
		severity = finding.Concern
		label = fmt.Sprintf("<c2pa:manifest> element that does not parse as a manifest (%d bytes)", len(m.Store))
	}

	out := finding.Set{
		finding.New(d.Name(), KindManifest, finding.Provenance, severity, span, label,
			"A signed record of where this document came from and what was done to it. "+
				"Unlike the rest of an SVG it is not drawn by anything, and unlike a credential "+
				"in a JPEG it is plain text sitting in the markup.",
		).WithDetail(finding.NewTable("c2pa", report.Rows())).Deletable(),
	}

	if report.Mismatched() {
		out = append(out, finding.New(d.Name(), KindBroken, finding.Provenance, finding.Concern,
			span, "the Content Credential no longer matches this document",
			"The manifest carries a hash over the document's bytes, and they no longer hash to "+
				"it. The document was changed after it was signed.",
		).WithDetail(finding.NewTable("c2pa-binding", []finding.KV{
			{Key: "algorithm", Value: report.Binding.Alg},
			{Key: "claim says", Value: report.Binding.Expected},
			{Key: "file hashes to", Value: report.Binding.Actual, Sensitive: true},
		})).Irremovable("Nothing can be removed to fix this: the mismatch is a fact about the "+
			"document's history, not an element in it."))
	}
	return out, nil
}
