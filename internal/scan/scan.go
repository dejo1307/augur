// Package scan is the engine: it decides what a file is, exposes the text inside
// it, runs the detectors that apply, and hands cleaning to the cleaner that owns
// each finding.
//
// It knows every detector and no detector knows it. That direction is the whole
// architecture — adding a detector is a line in Detectors() and nothing else.
package scan

import (
	"errors"
	"fmt"

	"github.com/dejo1307/augur/internal/clean"
	"github.com/dejo1307/augur/internal/detect/image"
	"github.com/dejo1307/augur/internal/detect/ooxml"
	"github.com/dejo1307/augur/internal/detect/pdf"
	"github.com/dejo1307/augur/internal/detect/text"
	"github.com/dejo1307/augur/pkg/detect"
	"github.com/dejo1307/augur/pkg/finding"
)

// Detectors is the registry. Order does not affect correctness — findings are
// sorted for display afterwards — so entries are grouped by what they look for.
func Detectors() []detect.Detector {
	return []detect.Detector{
		text.Hidden{},      // invisible runs, and what they decode to
		text.Bidi{},        // direction controls
		text.Control{},     // escape sequences and control characters
		text.Script{},      // mixed-alphabet and whole-word confusable words
		text.Styled{},      // words spelled in Unicode's alternate alphabets
		text.Markup{},      // text the document format hides from the rendered view
		text.Fingerprint{}, // the shape a distribution of them makes
		text.Space{},       // whitespace that is not a space
		text.Trailing{},    // whitespace past the end of a line
		text.Encoding{},    // BOM, invalid UTF-8

		image.Container{}, // metadata, provenance and stowaway bytes in images
		pdf.Container{},   // document metadata, invisible text, revisions left behind
		ooxml.Container{}, // hidden runs, tracked changes and properties in documents
	}
}

// Cleaners is the registry of things that can remove findings.
func Cleaners() []detect.Cleaner {
	return []detect.Cleaner{
		clean.Text{},
		clean.Image{},
	}
}

// Result is one file, scanned.
type Result struct {
	Source   *detect.Source
	Findings finding.Set
	// Errors holds detectors that failed. They are surfaced rather than swallowed:
	// a detector that silently errors makes a dirty file look clean, which is the
	// single worst thing this tool could do.
	Errors []error
}

// Clean reports whether the scan found nothing at all.
func (r Result) Clean() bool { return len(r.Findings) == 0 }

// Scan reads a file's bytes and returns everything the detectors found.
func Scan(path string, data []byte) Result {
	src := &detect.Source{
		Path:   path,
		Bytes:  data,
		Format: Sniff(data),
	}
	src.Regions = regions(src)

	res := Result{Source: src}
	for _, d := range Detectors() {
		if !d.Applies(src.Format) {
			continue
		}
		found, err := d.Detect(src)
		if err != nil {
			res.Errors = append(res.Errors, fmt.Errorf("detector %s: %w", d.Name(), err))
			continue
		}
		res.Findings = append(res.Findings, found...)
	}
	res.Findings.Sort()
	return res
}

// Sniff identifies a file from its leading bytes. Kept as a re-export so callers
// of the engine do not have to reach into the vocabulary package for it.
func Sniff(data []byte) detect.Format { return detect.Sniff(data) }

// regions exposes the text a file carries, for the text detectors to read.
//
// A text file is one region covering the whole thing, exactly. Image containers
// contribute one region per comment, XMP packet or text chunk they hold — which is
// how hidden characters buried in an image's metadata get found by the same
// detectors that read a .txt file, with no image-specific code in either of them.
// A format with no handler exposes nothing, and the text detectors stay silent
// about it rather than guessing.
func regions(src *detect.Source) []detect.Region {
	switch src.Format {
	case detect.Text:
		return []detect.Region{{
			Name:   "",
			Offset: 0,
			Text:   string(src.Bytes),
			Exact:  true,
		}}
	case detect.JPEG, detect.PNG, detect.WebP:
		return image.Regions(src.Bytes, src.Format)
	case detect.PDF:
		return pdf.Regions(src.Bytes)
	case detect.Office:
		return ooxml.Regions(src.Bytes)
	}
	return nil
}

// Apply removes the selected findings, routing each to the cleaner that owns it.
func Apply(src *detect.Source, all finding.Set, selected []finding.ID) ([]byte, error) {
	if len(selected) == 0 {
		out := make([]byte, len(src.Bytes))
		copy(out, src.Bytes)
		return out, nil
	}

	cleaner := CleanerFor(src.Format)
	if cleaner == nil {
		return nil, fmt.Errorf("%w: nothing can clean a %s file yet", ErrNotRemovable, src.Format)
	}

	// Check the whole selection before writing anything. A selection containing
	// something this cleaner cannot remove must fail loudly, because the
	// alternative is a caller writing a file in the belief that it was cleaned.
	owned := detect.Selected(cleaner, all, selected)
	if len(owned) != len(selected) {
		have := map[finding.ID]bool{}
		for _, f := range owned {
			have[f.ID] = true
		}
		var orphaned []finding.ID
		for _, id := range selected {
			if !have[id] {
				orphaned = append(orphaned, id)
			}
		}
		return nil, fmt.Errorf("%w: %v", ErrNotRemovable, orphaned)
	}

	data, err := cleaner.Clean(src.Bytes, all, selected)
	if err != nil {
		return nil, fmt.Errorf("cleaner %s: %w", cleaner.Name(), err)
	}
	return data, nil
}

// CleanerFor returns the single cleaner responsible for a format, or nil.
func CleanerFor(f detect.Format) detect.Cleaner {
	for _, c := range Cleaners() {
		if c.Applies(f) {
			return c
		}
	}
	return nil
}

// Removable reports the subset of a finding set that the cleaner for this format
// can actually remove — what "select all" should mean in the viewer.
func Removable(f detect.Format, all finding.Set) finding.Set {
	c := CleanerFor(f)
	if c == nil {
		return nil
	}
	var out finding.Set
	for _, x := range all {
		if c.Owns(x) {
			out = append(out, x)
		}
	}
	return out
}

// ErrNotRemovable reports a selection containing findings no cleaner can remove.
var ErrNotRemovable = errors.New("selected findings cannot be removed")
