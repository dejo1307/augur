// Package finding is augur's vocabulary: the shape of a single thing found
// hidden in a file, and the closed sets used to classify it.
//
// It is published under pkg/ so that a caller embedding augur as a library
// describes findings with the same words the TUI renders. It sits at the bottom of
// the layer order and imports nothing from this module.
package finding

import (
	"fmt"
	"sort"
)

// Category is what family a finding belongs to. Closed set — the TUI groups by it,
// the CLI filters by it, so a new category is a deliberate vocabulary addition.
type Category string

const (
	// Invisible: codepoints that render as nothing. Zero-width characters, tag
	// characters, variation selectors, private-use area, soft hyphen.
	Invisible Category = "invisible"
	// Bidi: direction-control codepoints, which can make source read differently
	// than it executes (Trojan Source, CVE-2021-42574).
	Bidi Category = "bidi"
	// Confusable: characters that look like other characters. Mixed-script tokens.
	Confusable Category = "confusable"
	// Whitespace: spaces that are not U+0020, and line/paragraph separators.
	Whitespace Category = "whitespace"
	// Encoding: byte-order marks, invalid or overlong UTF-8, lone surrogates.
	Encoding Category = "encoding"
	// Metadata: descriptive blocks carried alongside content. EXIF, XMP, IPTC,
	// ICC profiles, PNG text chunks, JPEG comments.
	Metadata Category = "metadata"
	// Provenance: claims about where the content came from. C2PA manifests,
	// generator and software tags. Reported neutrally; it is metadata with a
	// purpose, not an accusation.
	Provenance Category = "provenance"
	// Payload: data occupying space the format does not account for. Bytes after
	// a container's logical end, unexpectedly oversized segments.
	Payload Category = "payload"
	// Steganographic: a run of hidden characters that decoded to something. This
	// is the category that carries a recovered message rather than a count.
	Steganographic Category = "steganographic"
)

// Categories returns every category in display order: adversarial first, ambient last.
func Categories() []Category {
	return []Category{
		Steganographic, Bidi, Payload, Invisible, Confusable,
		Metadata, Provenance, Whitespace, Encoding,
	}
}

// Severity is how much a finding should worry the person reading it.
type Severity int

const (
	// Notice: present and benign. An ICC profile, a leading BOM. Worth seeing,
	// not worth alarm.
	Notice Severity = iota
	// Concern: identifying, or unexpected in a way that deserves a decision. GPS
	// coordinates, a device serial, a mixed-script word.
	Concern
	// Alarm: consistent with someone deliberately hiding something. A decoded
	// payload, bidi controls in source, bytes past the end of the container.
	Alarm
)

func (s Severity) String() string {
	switch s {
	case Notice:
		return "notice"
	case Concern:
		return "concern"
	case Alarm:
		return "alarm"
	default:
		return fmt.Sprintf("severity(%d)", int(s))
	}
}

// MarshalText makes severity readable in JSON output rather than an opaque integer.
func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// Kind is the specific thing found, finer-grained than Category. Detectors define
// their own kinds; the set is open because the long tail of smuggling schemes is
// the point. A kind is stable once shipped — it appears in JSON output and in the
// --categories style filters, so renaming one is a breaking change.
type Kind string

// Span locates a finding in the file.
//
// Offset and Length are always absolute into the original file's bytes when Exact
// is true, which is what makes a removal a byte-precise edit. When Exact is false
// the finding is real but its bytes are not directly addressable — it was found in
// text that had to be decompressed or re-decoded on the way out (a PNG zTXt chunk),
// and Offset/Length locate the enclosing region instead.
type Span struct {
	Offset int    `json:"offset"`
	Length int    `json:"length"`
	Region string `json:"region,omitempty"` // "" is the file itself; e.g. "xmp", "exif:ImageDescription"
	Exact  bool   `json:"exact"`
}

func (s Span) End() int { return s.Offset + s.Length }

// Overlaps reports whether two spans in the same region share any byte. Used to
// keep a selection from producing contradictory edits.
func (s Span) Overlaps(o Span) bool {
	return s.Region == o.Region && s.Offset < o.End() && o.Offset < s.End()
}

// ID identifies a finding within one scan of one file, stably enough that a
// selection made in the TUI still means the same thing when the session applies it.
//
// It is derived, not random: the same bytes scanned twice produce the same IDs, and
// two findings cannot share one because no detector emits the same kind twice at the
// same span in the same region.
type ID string

// NewID derives a finding's identity from what it is and where it is.
func NewID(kind Kind, span Span) ID {
	if span.Region == "" {
		return ID(fmt.Sprintf("%s@%d+%d", kind, span.Offset, span.Length))
	}
	return ID(fmt.Sprintf("%s@%s:%d+%d", kind, span.Region, span.Offset, span.Length))
}

// Finding is one hidden thing, found.
type Finding struct {
	ID       ID       `json:"id"`
	Detector string   `json:"detector"`
	Kind     Kind     `json:"kind"`
	Category Category `json:"category"`
	Severity Severity `json:"severity"`
	Span     Span     `json:"span"`

	// Label names the finding in one line, as a person would say it aloud:
	// "U+200B ZERO WIDTH SPACE", "GPS latitude", "C2PA manifest (41 KB)".
	Label string `json:"label"`
	// Why is one plain sentence explaining what this is and why it might be here.
	// Not a severity restatement — the reason someone would put it in a file.
	Why string `json:"why"`

	// Removable is false when augur can see this but cannot take it out
	// losslessly. Such findings are still reported; see docs/decisions/lossless-only.md.
	Removable bool `json:"removable"`
	// Replacement is what a cleaner writes in place of the span when this finding
	// is removed. nil deletes the span outright.
	//
	// The distinction is not decoration. Deleting a zero-width space is correct
	// because it was never meant to be read; deleting a non-breaking space would
	// silently join two words. A finding that needs a substitution says so here
	// rather than leaving the cleaner to guess.
	Replacement []byte `json:"replacement,omitempty"`

	// Detail is optional structured evidence: the decoded message, the codepoints,
	// the metadata table.
	Detail Detail `json:"detail,omitempty"`
}

// New builds a finding and derives its ID. Detectors should use this rather than
// constructing the struct literally, so identity derivation stays in one place.
func New(detector string, kind Kind, cat Category, sev Severity, span Span, label, why string) Finding {
	return Finding{
		ID:       NewID(kind, span),
		Detector: detector,
		Kind:     kind,
		Category: cat,
		Severity: sev,
		Span:     span,
		Label:    label,
		Why:      why,
		// Removable defaults to false on purpose: a detector claims removability
		// explicitly, because claiming it wrongly is how a tool corrupts a file.
		Removable: false,
	}
}

// WithDetail attaches structured evidence.
func (f Finding) WithDetail(d Detail) Finding { f.Detail = d; return f }

// Deletable marks the finding as removable by deleting its span outright. Only a
// detector that knows the exact bytes involved should call this — claiming
// removability wrongly is how a tool corrupts a file.
func (f Finding) Deletable() Finding {
	f.Removable = true
	f.Replacement = nil
	return f
}

// ReplaceableWith marks the finding as removable by substitution: the span is
// rewritten as `with` rather than dropped. Use it wherever deleting the bytes
// would change the surrounding text's meaning.
func (f Finding) ReplaceableWith(with []byte) Finding {
	f.Removable = true
	f.Replacement = with
	return f
}

// Irremovable states explicitly that this finding is reported but will not be
// touched, and why. The reason is shown to the user beside the finding, because
// "we found this and are leaving it" is only trustworthy if it says what stopped it.
func (f Finding) Irremovable(reason string) Finding {
	f.Removable = false
	f.Replacement = nil
	if reason != "" {
		f.Why = f.Why + " " + reason
	}
	return f
}

// Set is an ordered collection of findings, as returned by a scan.
type Set []Finding

// Sort orders findings for display: most severe first, then by position in the
// file, so the reading order matches the file's own order within a severity band.
func (s Set) Sort() {
	sort.SliceStable(s, func(i, j int) bool {
		if s[i].Severity != s[j].Severity {
			return s[i].Severity > s[j].Severity
		}
		if s[i].Span.Offset != s[j].Span.Offset {
			return s[i].Span.Offset < s[j].Span.Offset
		}
		return s[i].ID < s[j].ID
	})
}

// IDs returns the identities in the set, in its current order.
func (s Set) IDs() []ID {
	out := make([]ID, len(s))
	for i, f := range s {
		out[i] = f.ID
	}
	return out
}

// ByCategory groups the set for display.
func (s Set) ByCategory() map[Category]Set {
	out := make(map[Category]Set)
	for _, f := range s {
		out[f.Category] = append(out[f.Category], f)
	}
	return out
}

// Removable returns the subset that can be losslessly removed.
func (s Set) Removable() Set {
	var out Set
	for _, f := range s {
		if f.Removable {
			out = append(out, f)
		}
	}
	return out
}

// Worst returns the highest severity present, and false if the set is empty.
func (s Set) Worst() (Severity, bool) {
	if len(s) == 0 {
		return Notice, false
	}
	worst := s[0].Severity
	for _, f := range s[1:] {
		if f.Severity > worst {
			worst = f.Severity
		}
	}
	return worst, true
}
