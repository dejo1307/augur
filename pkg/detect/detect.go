// Package detect is the contract a detector implements and the contract a cleaner
// implements. It is the second half of augur's published vocabulary, and it
// sits at the bottom of the layer order beside pkg/finding.
//
// The rule this package exists to make enforceable: a detector receives a Source
// and returns findings. It cannot ask the engine a question, it cannot see the
// session, and it cannot reach the TUI. See docs/decisions/detector-contract.md.
package detect

import (
	"unicode/utf8"

	"github.com/dejo1307/augur/pkg/finding"
)

// Format is what the engine sniffed the file to be. Detectors use it to decide
// whether they apply at all.
type Format string

const (
	Unknown Format = "unknown"
	Text    Format = "text" // any valid UTF-8 that is not a known binary container
	JPEG    Format = "jpeg"
	PNG     Format = "png"
	WebP    Format = "webp"
	GIF     Format = "gif"
	Binary  Format = "binary" // recognised as binary, no handler claims it
)

// Region is a stretch of text inside the file that a format handler has exposed
// for the text detectors to look at. The whole of a plain text file is one region;
// an image contributes one region per XMP packet, comment, or text chunk it holds.
//
// The Exact distinction is load-bearing and is not a detail a detector may skip.
// When Exact is true, Text is a verbatim slice of the file's bytes starting at
// Offset, so a finding's byte span addresses real file bytes and can be removed by
// a precise edit. When Exact is false, Text was decompressed or re-decoded on the
// way out (a PNG zTXt chunk); the finding is real, but the only lossless way to
// remove it is for the format handler to drop the enclosing chunk.
type Region struct {
	Name   string // "" for the file itself; otherwise "xmp", "png:tEXt[Comment]", ...
	Offset int    // absolute offset of Text within the file, when Exact
	Text   string
	Exact  bool
}

// Span builds a file-absolute span for a finding at byte offset `at` within this
// region's Text, carrying the region's exactness with it. Detectors should use this
// rather than doing the arithmetic, so the Exact flag can never be forgotten.
func (r Region) Span(at, length int) finding.Span {
	if !r.Exact {
		// The finding is somewhere in this region, but its bytes are not
		// addressable. Point at the region as a whole and say so.
		return finding.Span{Offset: r.Offset, Length: 0, Region: r.Name, Exact: false}
	}
	return finding.Span{Offset: r.Offset + at, Length: length, Region: r.Name, Exact: true}
}

// Source is everything a detector is given.
type Source struct {
	// Path is where the file came from. Informational: a detector must not read
	// it, and must not read anything else off disk. Everything it may look at is
	// already in Bytes.
	Path string
	// Bytes is the file, entire and unmodified.
	Bytes []byte
	// Format is what the engine sniffed.
	Format Format
	// Regions are the text stretches available to text detectors. Empty for a
	// binary file whose handler exposed none.
	Regions []Region
}

// Detector finds things. One detector, one family of things.
type Detector interface {
	// Name identifies the detector in a finding's provenance and in --detectors
	// style filters. Stable once shipped.
	Name() string
	// Applies reports whether this detector has anything to say about a source of
	// this format. Checked before Detect, so Detect can assume it applies.
	Applies(f Format) bool
	// Detect returns what it found. A detector that finds nothing returns nil, nil
	// — not an error. An error means the detector could not do its job, which is
	// reported to the user rather than swallowed: a silent detector failure would
	// render as "this file is clean".
	Detect(src *Source) (finding.Set, error)
}

// Cleaner removes findings from a file.
//
// Exactly one cleaner handles any given file, chosen by format. That is a
// correctness requirement rather than a simplification: every edit shifts the
// offsets of the bytes after it, so a second cleaner running over the first one's
// output would be reading spans that no longer point where they did. One cleaner
// sees the whole selection and resolves it in a single pass.
type Cleaner interface {
	Name() string
	// Applies reports whether this cleaner handles files of this format.
	Applies(f Format) bool
	// Owns reports whether this cleaner can apply the given finding. A cleaner
	// must not own a finding it cannot remove losslessly.
	Owns(f finding.Finding) bool
	// Clean returns the file with the selected findings removed, and nothing else
	// changed. It must satisfy three properties, which are property-tested:
	//
	//   Clean(orig, {})        is byte-identical to orig
	//   Clean(Clean(x, S), S)  equals Clean(x, S)
	//   scan(Clean(orig, S))   equals scan(orig) minus S
	//
	// `all` is the complete finding set from the scan, not just the selection, so
	// a cleaner can reason about what it is leaving behind — a container rewrite
	// needs to know about the segments it is keeping.
	Clean(orig []byte, all finding.Set, selected []finding.ID) ([]byte, error)
}

// Selected is a convenience for cleaners: the subset of `all` whose IDs are in
// `selected` and which this cleaner owns.
func Selected(c Cleaner, all finding.Set, selected []finding.ID) finding.Set {
	want := make(map[finding.ID]struct{}, len(selected))
	for _, id := range selected {
		want[id] = struct{}{}
	}
	var out finding.Set
	for _, f := range all {
		if _, ok := want[f.ID]; !ok {
			continue
		}
		if c.Owns(f) {
			out = append(out, f)
		}
	}
	return out
}

// Sniff identifies the file from its leading bytes, never from its extension. A
// name is a claim by whoever wrote the file; the magic bytes are what it is.
func Sniff(data []byte) Format {
	switch {
	case len(data) == 0:
		return Text // an empty file is trivially valid text
	case has(data, []byte{0xFF, 0xD8, 0xFF}):
		return JPEG
	case has(data, []byte("\x89PNG\r\n\x1a\n")):
		return PNG
	case has(data, []byte("GIF87a")), has(data, []byte("GIF89a")):
		return GIF
	case len(data) >= 12 && string(data[0:4]) == "RIFF" && string(data[8:12]) == "WEBP":
		return WebP
	}
	if looksTextual(data) {
		return Text
	}
	return Binary
}

func has(data, prefix []byte) bool {
	return len(data) >= len(prefix) && string(data[:len(prefix)]) == string(prefix)
}

// looksTextual decides whether a file should be read as characters.
//
// Valid UTF-8 alone is too weak a test — plenty of binary formats are accidentally
// valid UTF-8 — and requiring it outright is too strong, because a text file with
// a few corrupt bytes is exactly a file this tool should have an opinion about. So:
// no NUL bytes, and the great majority of it decodes.
func looksTextual(data []byte) bool {
	const sample = 8192
	head := data
	if len(head) > sample {
		head = head[:sample]
		for len(head) > 0 && !utf8.RuneStart(head[len(head)-1]) {
			head = head[:len(head)-1]
		}
	}
	bad := 0
	for i := 0; i < len(head); {
		if head[i] == 0x00 {
			return false // NUL is the classic binary tell
		}
		r, size := utf8.DecodeRune(head[i:])
		if r == utf8.RuneError && size == 1 {
			bad++
			i++
			continue
		}
		i += size
	}
	return bad*100 <= len(head)*5
}
