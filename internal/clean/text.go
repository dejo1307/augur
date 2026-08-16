// Package clean removes findings from a file. There is one cleaner per format
// family, and each owns only the findings it can remove losslessly.
//
// "Losslessly" is not a slogan here, it is the type system: a cleaner declines to
// own anything it cannot remove byte-exactly, so there is no path through this
// package that alters a byte nobody asked about. See docs/decisions/lossless-only.md.
package clean

import (
	"fmt"
	"sort"

	"github.com/dejo1307/augur/pkg/detect"
	"github.com/dejo1307/augur/pkg/finding"
)

// Text removes findings from a text file by editing the exact bytes they occupy:
// deleting a span, or replacing it with the finding's stated substitute.
type Text struct{}

func (Text) Name() string { return "text" }

// Applies claims plain text files. Text found inside an image container is not
// this cleaner's business even though it is text: removing it means rewriting the
// container, and that belongs to the cleaner that understands the container.
func (Text) Applies(f detect.Format) bool { return f == detect.Text }

// Owns claims the findings this cleaner can act on: removable ones, located
// exactly, in the file itself rather than inside a container's re-encoded block.
//
// Declining the rest is the point. A finding inside a JPEG's XMP packet has an
// exact file offset too, but editing those bytes would leave the enclosing
// segment's length field lying about its own size — so the image cleaner owns it,
// and this one says no.
func (Text) Owns(f finding.Finding) bool {
	return f.Removable && f.Span.Exact && f.Span.Region == ""
}

// Clean applies the selected edits and changes nothing else.
func (t Text) Clean(orig []byte, all finding.Set, selected []finding.ID) ([]byte, error) {
	edits := edits(t, all, selected)
	if len(edits) == 0 {
		// Byte-identical, and the same backing array is never handed out: a
		// caller that mutates the result must not be able to reach the original.
		out := make([]byte, len(orig))
		copy(out, orig)
		return out, nil
	}

	sort.Slice(edits, func(i, j int) bool { return edits[i].Span.Offset < edits[j].Span.Offset })

	for i := 1; i < len(edits); i++ {
		if edits[i-1].Span.Overlaps(edits[i].Span) {
			// Two detectors claiming the same bytes is a bug in the detectors, not
			// a condition to resolve here by picking a winner. Refuse and name both.
			return nil, fmt.Errorf("clean: overlapping edits %q and %q both claim bytes at %d",
				edits[i-1].ID, edits[i].ID, edits[i].Span.Offset)
		}
	}
	if last := edits[len(edits)-1].Span; last.End() > len(orig) {
		return nil, fmt.Errorf("clean: finding %q spans past the end of the file (%d > %d)",
			edits[len(edits)-1].ID, last.End(), len(orig))
	}

	out := make([]byte, 0, len(orig))
	at := 0
	for _, e := range edits {
		out = append(out, orig[at:e.Span.Offset]...)
		out = append(out, e.Replacement...) // nil for a deletion
		at = e.Span.End()
	}
	return append(out, orig[at:]...), nil
}

// edits is the selection this cleaner owns, in no particular order.
func edits(c interface{ Owns(finding.Finding) bool }, all finding.Set, selected []finding.ID) finding.Set {
	want := make(map[finding.ID]struct{}, len(selected))
	for _, id := range selected {
		want[id] = struct{}{}
	}
	var out finding.Set
	for _, f := range all {
		if _, ok := want[f.ID]; ok && c.Owns(f) {
			out = append(out, f)
		}
	}
	return out
}
