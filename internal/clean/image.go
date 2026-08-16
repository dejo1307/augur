package clean

import (
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/dejo1307/augur/internal/detect/image"
	"github.com/dejo1307/augur/pkg/detect"
	"github.com/dejo1307/augur/pkg/finding"
)

// Image removes findings from an image by rewriting the container without the
// blocks they occupy.
//
// It never touches compressed pixel data. A cleaned JPEG's entropy-coded scan is
// copied through byte for byte, which is what makes "lossless" a fact about the
// implementation rather than a claim in the README. The only structural fix-up is
// the RIFF size field in a WebP header, which counts the bytes that follow it and
// would otherwise describe a file that no longer exists.
type Image struct{}

func (Image) Name() string { return "image" }

func (Image) Applies(f detect.Format) bool {
	switch f {
	case detect.JPEG, detect.PNG, detect.WebP:
		return true
	}
	return false
}

// Owns claims whole-block findings in an image.
//
// It also claims findings the *text* detectors made inside a metadata block —
// a hidden message in an XMP packet, say. Those have exact file offsets, so the
// text cleaner could edit them, and it must not: the enclosing segment carries a
// length field, and shortening the text without rewriting that field produces a
// file that every decoder reads as corrupt. Removing the block is the lossless
// answer, and this cleaner is the one that can give it.
func (Image) Owns(f finding.Finding) bool {
	return f.Removable && f.Span.Exact
}

func (c Image) Clean(orig []byte, all finding.Set, selected []finding.ID) ([]byte, error) {
	want := make(map[finding.ID]struct{}, len(selected))
	for _, id := range selected {
		want[id] = struct{}{}
	}

	format := formatOf(orig)
	w, err := walkFor(orig, format)
	if err != nil {
		return nil, err
	}

	// Work out which byte ranges to drop. A finding either names a block outright
	// or sits inside one; either way the whole block goes.
	drop := map[int]blockRange{} // keyed by block offset, so two findings in one block drop it once
	for _, f := range all {
		if _, ok := want[f.ID]; !ok {
			continue
		}
		if !c.Owns(f) {
			return nil, fmt.Errorf("finding %q is not this cleaner's to remove", f.ID)
		}

		// Trailing bytes are not a block; they are everything after the last one.
		if w.hasTrailing && f.Span.Offset == w.trailingOffset {
			drop[f.Span.Offset] = blockRange{start: f.Span.Offset, end: f.Span.Offset + f.Span.Length}
			continue
		}

		b, ok := w.containing(f.Span.Offset)
		if !ok {
			return nil, fmt.Errorf("finding %q at offset %d is not inside any block",
				f.ID, f.Span.Offset)
		}
		if b.essential {
			// Refuse rather than produce a broken image. Reaching here means a
			// detector marked something removable that is load-bearing.
			return nil, fmt.Errorf("finding %q is inside the essential block %q; removing it would break the image",
				f.ID, b.kind)
		}
		drop[b.start] = b
	}

	if len(drop) == 0 {
		out := make([]byte, len(orig))
		copy(out, orig)
		return out, nil
	}

	ranges := make([]blockRange, 0, len(drop))
	for _, r := range drop {
		ranges = append(ranges, r)
	}
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].start < ranges[j].start })

	out := make([]byte, 0, len(orig))
	at := 0
	for _, r := range ranges {
		if r.start < at {
			return nil, fmt.Errorf("overlapping blocks at offset %d", r.start)
		}
		out = append(out, orig[at:r.start]...)
		at = r.end
	}
	out = append(out, orig[at:]...)

	if format == detect.WebP {
		out = fixRIFFSize(out)
	}
	return out, nil
}

// formatOf re-sniffs the bytes rather than taking the format on trust. The
// cleaner is handed raw bytes by the interface, and re-deriving what they are is
// both cheap and the only way to be sure a JPEG walker is not pointed at a PNG.
func formatOf(data []byte) detect.Format { return detect.Sniff(data) }

// walkFor reduces a container to the ranges the rewrite cares about.
func walkFor(data []byte, f detect.Format) (layout, error) {
	var w image.Walk
	var err error
	switch f {
	case detect.JPEG:
		w, err = image.WalkJPEG(data)
	case detect.PNG:
		w, err = image.WalkPNG(data)
	case detect.WebP:
		w, err = image.WalkWebP(data)
	default:
		return layout{}, fmt.Errorf("no container walker for %s", f)
	}
	if err != nil {
		return layout{}, err
	}

	l := layout{}
	for _, b := range w.Blocks {
		l.blocks = append(l.blocks, blockRange{
			start: b.Offset, end: b.Offset + b.Length, kind: b.Kind, essential: b.Essential,
		})
	}
	if len(w.Trailing) > 0 {
		l.hasTrailing = true
		l.trailingOffset = w.TrailingOffset
	}
	return l, nil
}

// blockRange is a block reduced to what the rewrite needs to know about it.
type blockRange struct {
	start, end int
	kind       string
	essential  bool
}

type layout struct {
	blocks         []blockRange
	hasTrailing    bool
	trailingOffset int
}

func (l layout) containing(off int) (blockRange, bool) {
	for _, b := range l.blocks {
		if off >= b.start && off < b.end {
			return b, true
		}
	}
	return blockRange{}, false
}

// fixRIFFSize rewrites a WebP's RIFF size field, which counts every byte after
// itself. Dropping a chunk without updating it leaves the header describing a file
// that is no longer there.
func fixRIFFSize(out []byte) []byte {
	if len(out) < 12 {
		return out
	}
	binary.LittleEndian.PutUint32(out[4:8], uint32(len(out)-8))
	return out
}
