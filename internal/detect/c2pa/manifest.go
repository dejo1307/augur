// Package c2pa reads Content Credentials: the signed provenance manifest a
// generator attaches to a file to record what made it and what has been done to
// it since.
//
// augur reads these because a manifest is the one piece of metadata that makes a
// claim about the file it rides in — including a cryptographic one. The claim is
// bound to the bytes by a hash over them, and that hash can be checked here with
// nothing but the file: if it no longer matches, the file was changed after it
// was signed. That is the rare provenance question a tool can answer for itself
// rather than by asking a vendor.
//
// What this package does NOT do: decide whether the signer is trustworthy. That
// is a question about certificate trust lists, and answering it half-way — "the
// certificate parsed" reported as "verified" — would be the kind of claim augur
// exists not to make.
package c2pa

import (
	"errors"
	"fmt"
	"strings"
)

// Labels the C2PA specification gives the parts of a manifest.
const (
	labelStore      = "c2pa"
	labelAssertions = "c2pa.assertions"
	labelClaim      = "c2pa.claim"
	labelClaimV2    = "c2pa.claim.v2"
	labelSignature  = "c2pa.signature"

	labelDataHash       = "c2pa.hash.data"
	labelBoxHash        = "c2pa.hash.boxes"
	labelBMFFHash       = "c2pa.hash.bmff"
	labelCollectionHash = "c2pa.hash.collection.data"
	labelActions        = "c2pa.actions"
)

// ErrNoManifest reports bytes that are not a C2PA manifest store.
var ErrNoManifest = errors.New("no C2PA manifest store here")

// Store is a parsed manifest store: the chain of manifests a file carries.
//
// Order is load-bearing. The last standard manifest is the active one — the claim
// about this file — and the ones before it describe ingredients that went into
// it. A hard binding belongs to the manifest that made it, so checking an
// ingredient's binding against this file would report a mismatch for a file that
// is perfectly intact.
type Store struct {
	Manifests []Manifest
	// Truncated is set when the store ended mid-box. What was read before that
	// point is still reported: a manifest cut short is itself a finding.
	Truncated bool
}

// Manifest is one claim and everything it signs over.
type Manifest struct {
	Label      string // the manifest's URN
	Update     bool   // an update manifest: metadata about an existing claim
	Claim      any    // the decoded claim, a CBOR map
	ClaimLabel string // "c2pa.claim" (v1) or "c2pa.claim.v2"
	Assertions []Assertion
	Signature  []byte // the COSE_Sign1 structure, undecoded
}

// Assertion is one statement inside a manifest.
type Assertion struct {
	Label string
	// Value is the decoded assertion for the CBOR and JSON forms, and nil for a
	// thumbnail or any other assertion whose body is a blob.
	Value any
	Size  int
}

// Parse reads a manifest store.
func Parse(store []byte) (*Store, error) {
	p := &boxParser{}
	boxes := p.boxes(store, 0, 0)
	if len(boxes) == 0 {
		return nil, ErrNoManifest
	}

	// The store's own label is "c2pa", with room in the specification for a
	// version suffix on it. Matching the prefix accepts the next version of the
	// format rather than reporting a file that carries a credential as carrying
	// none.
	top := boxes[0]
	if top.Type != boxSuper || !strings.HasPrefix(top.Label, labelStore) {
		return nil, ErrNoManifest
	}

	s := &Store{Truncated: p.truncated}
	for _, m := range top.Children {
		if m.Type != boxSuper {
			continue
		}
		s.Manifests = append(s.Manifests, readManifest(m))
	}
	if len(s.Manifests) == 0 {
		return nil, ErrNoManifest
	}
	return s, nil
}

// Active returns the manifest whose claim is about this file: the last standard
// manifest in the store, per the C2PA specification's rule for which claim is
// live. An update manifest is skipped rather than treated as the claim, because
// it carries no hard binding of its own.
func (s *Store) Active() *Manifest {
	for i := len(s.Manifests) - 1; i >= 0; i-- {
		if !s.Manifests[i].Update {
			return &s.Manifests[i]
		}
	}
	if len(s.Manifests) == 0 {
		return nil
	}
	return &s.Manifests[len(s.Manifests)-1]
}

// Ingredients counts the manifests that are not the active one: the assets this
// file was made from, each with its own claim.
func (s *Store) Ingredients() int {
	if len(s.Manifests) == 0 {
		return 0
	}
	return len(s.Manifests) - 1
}

func readManifest(box Box) Manifest {
	m := Manifest{
		Label:  box.Label,
		Update: contentType(box.UUID) == "update manifest",
	}
	for _, child := range box.Children {
		switch child.Label {
		case labelClaim, labelClaimV2:
			m.ClaimLabel = child.Label
			m.Claim = decodeContent(child)
		case labelSignature:
			m.Signature = signatureBytes(child)
		case labelAssertions:
			for _, a := range child.Children {
				m.Assertions = append(m.Assertions, Assertion{
					Label: a.Label,
					Value: decodeContent(a),
					Size:  a.Length,
				})
			}
		}
	}
	return m
}

// Assertion returns the named assertion, and whether the manifest had one.
//
// The match is by base label rather than exact string, because C2PA versions and
// numbers its assertion labels in place: the actions assertion is "c2pa.actions"
// in a v1 manifest, "c2pa.actions.v2" in a v2 one, and "c2pa.actions__1" when a
// manifest carries more than one of them. Matching exactly means silently
// reporting "no actions" for every current file, which is worse than not looking.
func (m *Manifest) Assertion(label string) (Assertion, bool) {
	for _, a := range m.Assertions {
		if a.Label == label {
			return a, true
		}
	}
	for _, a := range m.Assertions {
		if sameAssertion(a.Label, label) {
			return a, true
		}
	}
	return Assertion{}, false
}

// sameAssertion reports whether a label is the base label with a version or
// instance suffix on it.
func sameAssertion(label, base string) bool {
	if !strings.HasPrefix(label, base) {
		return false
	}
	rest := label[len(base):]
	for rest != "" {
		switch {
		case strings.HasPrefix(rest, ".v"):
			rest = strings.TrimLeft(rest[2:], "0123456789")
			if strings.HasPrefix(rest, ".v") || rest == "" || strings.HasPrefix(rest, "__") {
				continue
			}
			return false
		case strings.HasPrefix(rest, "__"):
			rest = strings.TrimLeft(rest[2:], "0123456789")
			if rest == "" {
				return true
			}
			return false
		default:
			return false
		}
	}
	return true
}

// Generator names the software that made the claim, as it named itself.
func (m *Manifest) Generator() string {
	// v2 manifests carry a structured list; v1 carries a user-agent-ish string.
	// Both are reported as the producer said them rather than normalised, because
	// "which tool wrote this" is a quotation, not an interpretation.
	// v1 writes a list of generators, v2 a single one. Both shapes appear in
	// files being produced today.
	info := cborGet(m.Claim, "claim_generator_info")
	if list := cborArray(info); len(list) > 0 {
		info = list[0]
	}
	if name := softwareAgent(info); name != "" {
		return name
	}
	return cborString(cborGet(m.Claim, "claim_generator"))
}

// ClaimVersion reports 1 or 2, from which box label the claim arrived in.
func (m *Manifest) ClaimVersion() int {
	if m.ClaimLabel == labelClaimV2 {
		return 2
	}
	return 1
}

// Actions summarises the c2pa.actions assertion: what was done to this asset,
// and — the row that matters for a generated file — what the producer says the
// source of the pixels or the words was.
type Actions struct {
	// Names are the action labels in order: "c2pa.created", "c2pa.edited", ...
	Names []string
	// SoftwareAgent is what the producer named as having performed them.
	SoftwareAgent string
	// DigitalSourceType is the IPTC term the producer recorded, plainly worded.
	// This is where a file says it came out of a model.
	DigitalSourceType string
	// When is the time the producer recorded against an action, if any.
	When string
}

func (m *Manifest) Actions() (Actions, bool) {
	a, ok := m.Assertion(labelActions)
	if !ok {
		return Actions{}, false
	}
	list := cborArray(cborGet(a.Value, "actions"))
	if len(list) == 0 {
		return Actions{}, false
	}
	var out Actions
	for _, item := range list {
		name := cborString(cborGet(item, "action"))
		if name != "" {
			out.Names = append(out.Names, name)
		}
		if out.SoftwareAgent == "" {
			out.SoftwareAgent = softwareAgent(cborGet(item, "softwareAgent"))
		}
		if out.DigitalSourceType == "" {
			out.DigitalSourceType = cborString(cborGet(item, "digitalSourceType"))
		}
		if out.When == "" {
			out.When = cborString(cborGet(item, "when"))
		}
	}
	// The assertion may name the agent once for the whole set rather than per
	// action.
	if out.SoftwareAgent == "" {
		out.SoftwareAgent = softwareAgent(cborGet(a.Value, "softwareAgent"))
	}
	return out, true
}

// softwareAgent reads the field in both the shapes the spec has used: a bare
// string in v1, and a generator-info map in v2.
func softwareAgent(v any) string {
	if s := cborString(v); s != "" {
		return s
	}
	name := cborString(cborGet(v, "name"))
	version := cborString(cborGet(v, "version"))
	switch {
	case name != "" && version != "":
		return name + " " + version
	default:
		return name
	}
}

// SourceType turns an IPTC digital source type URI into the sentence it stands
// for. The vocabulary is small and its terms are the whole point of the
// assertion, so leaving the reader to look up a URI would be reporting the
// pointer instead of the fact.
func SourceType(uri string) string {
	term := uri
	if i := strings.LastIndex(uri, "/"); i >= 0 {
		term = uri[i+1:]
	}
	switch term {
	case "trainedAlgorithmicMedia":
		return "generated by a trained model"
	case "compositeWithTrainedAlgorithmicMedia":
		return "part generated by a trained model"
	case "trainedAlgorithmicData":
		return "data generated by a trained model"
	case "algorithmicMedia":
		return "generated by an algorithm"
	case "digitalCapture":
		return "captured by a camera or recorder"
	case "negativeFilm", "positiveFilm", "print":
		return "digitised from film or print"
	case "humanEdits":
		return "edited by a person"
	case "composite", "compositeCapture", "compositeSynthetic":
		return "composited from more than one source"
	case "algorithmicallyEnhanced":
		return "algorithmically enhanced"
	case "softwareImage":
		return "created in software"
	case "":
		return ""
	}
	return term
}

// decodeContent reads an assertion or claim box's body. A CBOR or JSON box
// decodes; anything else (a thumbnail, a compressed box) is left alone, and its
// label plus size is what gets reported.
func decodeContent(box Box) any {
	for _, c := range box.Children {
		switch c.Type {
		case boxCBOR:
			v, err := cborDecode(c.Payload)
			if err != nil {
				return nil
			}
			return v
		case boxJSON:
			return jsonDecode(c.Payload)
		}
	}
	// A claim box may be a content box directly rather than a superbox.
	if box.Type == boxCBOR {
		v, err := cborDecode(box.Payload)
		if err != nil {
			return nil
		}
		return v
	}
	return nil
}

// signatureBytes pulls the COSE structure out of a signature box.
//
// Two shapes are in the wild: a CBOR content box holding the COSE_Sign1 directly,
// which is what current writers produce, and a UUID content box whose first 16
// bytes are the type UUID and whose remainder is the same structure.
func signatureBytes(box Box) []byte {
	for _, c := range box.Children {
		switch {
		case c.Type == boxCBOR && len(c.Payload) > 0:
			return c.Payload
		case c.Type == boxUUID && len(c.Payload) > 16:
			return c.Payload[16:]
		}
	}
	return nil
}

// String renders a manifest for debugging and for the error paths that need to
// name one.
func (m *Manifest) String() string {
	return fmt.Sprintf("manifest %s (%s, %d assertions)", m.Label, m.ClaimLabel, len(m.Assertions))
}
