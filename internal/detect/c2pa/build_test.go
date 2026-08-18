package c2pa

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sort"
	"testing"
)

// The builders below write the formats this package reads: CBOR values and JUMBF
// boxes. They exist so the tests can state a manifest as a Go value and check
// what augur makes of it, rather than pointing at a signed file somebody else
// produced and hoping it stays reachable.
//
// A signed corpus is not a substitute for this and this is not a substitute for
// one. These cover the shapes — a v2 claim, a broken binding, a truncated store —
// that no fixture on disk happens to have.

// cborEncode writes the subset of CBOR a manifest uses.
func cborEncode(v any) []byte {
	switch t := v.(type) {
	case nil:
		return []byte{0xf6}
	case bool:
		if t {
			return []byte{0xf5}
		}
		return []byte{0xf4}
	case int:
		return cborHead(0, uint64(t))
	case int64:
		return cborHead(0, uint64(t))
	case string:
		return append(cborHead(3, uint64(len(t))), t...)
	case []byte:
		return append(cborHead(2, uint64(len(t))), t...)
	case []any:
		out := cborHead(4, uint64(len(t)))
		for _, item := range t {
			out = append(out, cborEncode(item)...)
		}
		return out
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := cborHead(5, uint64(len(keys)))
		for _, k := range keys {
			out = append(out, cborEncode(k)...)
			out = append(out, cborEncode(t[k])...)
		}
		return out
	}
	panic("cborEncode: unsupported type")
}

// cborEncodeIndefinite writes a map in the streaming form, which is what the CBOR
// libraries most producers use emit for a struct.
func cborEncodeIndefinite(m map[string]any) []byte {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := []byte{0xbf} // map, indefinite length
	for _, k := range keys {
		out = append(out, cborEncode(k)...)
		out = append(out, cborEncode(m[k])...)
	}
	return append(out, 0xff)
}

func cborHead(major byte, arg uint64) []byte {
	switch {
	case arg < 24:
		return []byte{major<<5 | byte(arg)}
	case arg < 1<<8:
		return []byte{major<<5 | 24, byte(arg)}
	case arg < 1<<16:
		b := []byte{major<<5 | 25, 0, 0}
		binary.BigEndian.PutUint16(b[1:], uint16(arg))
		return b
	case arg < 1<<32:
		b := []byte{major<<5 | 26, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(b[1:], uint32(arg))
		return b
	default:
		b := []byte{major<<5 | 27, 0, 0, 0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint64(b[1:], arg)
		return b
	}
}

// The content type UUIDs C2PA gives its boxes.
const (
	uuidStore     = "6332706100110010800000AA00389B71"
	uuidManifest  = "63326D6100110010800000AA00389B71"
	uuidUpdate    = "6332756D00110010800000AA00389B71"
	uuidAssertion = "6332617300110010800000AA00389B71"
	uuidClaim     = "6332636C00110010800000AA00389B71"
	uuidSignature = "6332637300110010800000AA00389B71"
	uuidCBOR      = "63626F7200110010800000AA00389B71"
	uuidJSON      = "6A736F6E00110010800000AA00389B71"
)

// contentBox writes a leaf box: a length, a type, and a payload.
func contentBox(typ string, payload []byte) []byte {
	out := make([]byte, 8, 8+len(payload))
	binary.BigEndian.PutUint32(out[0:4], uint32(8+len(payload)))
	copy(out[4:8], typ)
	return append(out, payload...)
}

// superBox writes a superbox: a description box naming it, then its children.
func superBox(label, uuidHex string, children ...[]byte) []byte {
	payload := describeBox(label, uuidHex)
	for _, c := range children {
		payload = append(payload, c...)
	}
	return contentBox(boxSuper, payload)
}

func describeBox(label, uuidHex string) []byte {
	uuid, err := hex.DecodeString(uuidHex)
	if err != nil {
		panic(err)
	}
	payload := append([]byte{}, uuid...)
	payload = append(payload, 0x03) // requestable + label present
	payload = append(payload, label...)
	payload = append(payload, 0x00)
	return contentBox(boxDescription, payload)
}

// manifestOptions is what a test wants to vary about the store it builds.
type manifestOptions struct {
	label      string
	claimLabel string
	claim      map[string]any
	assertions map[string]any // label -> CBOR value
	update     bool
	signature  []byte
}

// buildStore assembles a manifest store from a description of one manifest.
func buildStore(t *testing.T, o manifestOptions) []byte {
	t.Helper()
	if o.label == "" {
		o.label = "urn:uuid:00000000-0000-0000-0000-00000000test"
	}
	if o.claimLabel == "" {
		o.claimLabel = labelClaim
	}

	labels := make([]string, 0, len(o.assertions))
	for label := range o.assertions {
		labels = append(labels, label)
	}
	sort.Strings(labels)

	var assertionBoxes [][]byte
	for _, label := range labels {
		assertionBoxes = append(assertionBoxes,
			superBox(label, uuidCBOR, contentBox(boxCBOR, cborEncode(o.assertions[label]))))
	}

	manifestUUID := uuidManifest
	if o.update {
		manifestUUID = uuidUpdate
	}

	children := [][]byte{
		superBox(labelAssertions, uuidAssertion, assertionBoxes...),
		superBox(o.claimLabel, uuidClaim, contentBox(boxCBOR, cborEncodeIndefinite(o.claim))),
	}
	if o.signature != nil {
		children = append(children, superBox(labelSignature, uuidSignature,
			contentBox(boxCBOR, o.signature)))
	}

	return superBox(labelStore, uuidStore, superBox(o.label, manifestUUID, children...))
}

// dataHash builds a c2pa.hash.data assertion over `file` with `ranges` excluded.
// The hash is computed the way a producer computes it, so a store built with it
// is one augur should call a match.
func dataHash(file []byte, ranges ...[2]int) map[string]any {
	h := sha256.New()
	at := 0
	var exclusions []any
	for _, r := range ranges {
		if r[0] > at {
			h.Write(file[at:r[0]])
		}
		at = r[1]
		exclusions = append(exclusions, map[string]any{"start": r[0], "length": r[1] - r[0]})
	}
	if at < len(file) {
		h.Write(file[at:])
	}
	return map[string]any{
		"exclusions": exclusions,
		"name":       "jumbf manifest",
		"alg":        "sha256",
		"hash":       h.Sum(nil),
	}
}

// StoreFor builds a manifest store whose data hash covers `file` with `ranges`
// excluded, and whose claim says a model made the asset.
//
// Exported so the end-to-end tests — which live in the external test package
// because they reach through the engine and the container handlers — can build
// the same fixtures the unit tests do.
func StoreFor(t *testing.T, generator, sourceType string, file []byte, ranges ...[2]int) []byte {
	t.Helper()
	return storeFor(t, generator, sourceType, 0, file, ranges...)
}

// BulkyStoreFor is StoreFor with `bulk` bytes of assertion padding, for tests that
// need a store too large to fit in one JPEG segment. Real stores reach that size
// through thumbnails; the padding stands in for one.
func BulkyStoreFor(t *testing.T, generator string, bulk int, file []byte, ranges ...[2]int) []byte {
	t.Helper()
	return storeFor(t, generator, "", bulk, file, ranges...)
}

func storeFor(t *testing.T, generator, sourceType string, bulk int, file []byte, ranges ...[2]int) []byte {
	t.Helper()
	assertions := map[string]any{labelDataHash: dataHash(file, ranges...)}
	if bulk > 0 {
		assertions["c2pa.thumbnail.claim"] = map[string]any{"data": make([]byte, bulk)}
	}
	if sourceType != "" {
		assertions[labelActions] = map[string]any{"actions": []any{map[string]any{
			"action":            "c2pa.created",
			"softwareAgent":     generator,
			"digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/" + sourceType,
		}}}
	}
	return buildStore(t, manifestOptions{
		claim: map[string]any{
			"claim_generator_info": []any{map[string]any{"name": generator}},
			"alg":                  "sha256",
		},
		assertions: assertions,
	})
}

// SettleStore builds a store for a container whose own size depends on the
// store's, which is every container: the exclusion range in the claim names the
// bytes the manifest occupies, and CBOR writes a larger number in more bytes.
//
// `embed` places a store of the given length into the file and says which byte
// range it occupies. It is called until the length stops moving.
func SettleStore(t *testing.T, embed func(store []byte) (file []byte, at [2]int), generator, sourceType string) []byte {
	t.Helper()
	size := 0
	for pass := 0; pass < 8; pass++ {
		file, at := embed(make([]byte, size))
		store := StoreFor(t, generator, sourceType, file, at)
		if len(store) == size {
			return store
		}
		size = len(store)
	}
	t.Fatal("the store's length never settled")
	return nil
}
