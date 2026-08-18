package c2pa

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// JUMBF is the box format a C2PA manifest store is written in (ISO/IEC 19566-5).
// It is BMFF-shaped: a length, a four-character type, and a payload — where a
// superbox's payload is more boxes, and the first of them describes the superbox
// it is in.
//
// This reads the structure and nothing more. What the boxes mean is manifest.go's
// question; keeping the two apart is what makes the box reader safe to point at a
// hostile file.

const (
	boxSuper       = "jumb" // superbox: its payload is more boxes
	boxDescription = "jumd" // describes the superbox it opens
	boxCBOR        = "cbor"
	boxJSON        = "json"
	boxUUID        = "uuid"
)

// jumbfMaxDepth bounds recursion. A real manifest store nests about six deep;
// this leaves room for the ones nobody has written yet without letting a crafted
// file walk the stack down.
const jumbfMaxDepth = 24

// Box is one JUMBF box, with a superbox's description already folded in.
type Box struct {
	// Type is the four-character code: "jumb" for a superbox, "cbor", "json",
	// "uuid", "bidb" and so on for content.
	Type string
	// Label and UUID come from a superbox's description box. Label is what
	// names a box in the C2PA structure — "c2pa", "c2pa.assertions",
	// "c2pa.hash.data" — and UUID is its content type, which is how an update
	// manifest (c2um) is told from a standard one (c2ma).
	Label string
	UUID  [16]byte
	// Payload is a content box's bytes, without its header. Nil for a superbox.
	Payload []byte
	// Children are a superbox's contents, description box excluded.
	Children []Box
	// Offset and Length locate the box within the bytes it was parsed from.
	Offset, Length int
}

// boxParser walks a run of boxes without giving up on the first one that does not
// add up.
//
// Best-effort is the right posture here rather than a concession. A manifest store
// that was cut short — by a truncated download, a segment that got dropped, a
// producer that miscounted — still holds real statements in the boxes that did
// arrive, and reporting those plus "this is cut short" tells the reader more than
// reporting nothing at all. What it never does is read past the bytes it was
// given: a length longer than the input is clamped to the input, and the store is
// marked truncated.
type boxParser struct {
	truncated bool
}

func (p *boxParser) boxes(data []byte, base, depth int) []Box {
	if depth > jumbfMaxDepth {
		p.truncated = true
		return nil
	}
	var out []Box
	at := 0
	for at < len(data) {
		b, n, ok := p.box(data[at:], base+at, depth)
		if !ok {
			p.truncated = true
			break
		}
		out = append(out, b)
		at += n
	}
	return out
}

// box reads one box and returns how many bytes it occupied.
func (p *boxParser) box(data []byte, offset, depth int) (Box, int, bool) {
	if len(data) < 8 {
		return Box{}, 0, false
	}
	size := int(binary.BigEndian.Uint32(data[0:4]))
	typ := string(data[4:8])
	header := 8

	switch size {
	case 0:
		// The box runs to the end of the enclosing container.
		size = len(data)
	case 1:
		// XLBox: a 64-bit length follows the type.
		if len(data) < 16 {
			return Box{}, 0, false
		}
		xl := binary.BigEndian.Uint64(data[8:16])
		if xl < 16 {
			return Box{}, 0, false
		}
		size = len(data)
		if xl <= uint64(len(data)) {
			size = int(xl)
		} else {
			p.truncated = true
		}
		header = 16
	}
	if size < header {
		return Box{}, 0, false
	}
	if size > len(data) {
		size = len(data)
		p.truncated = true
	}

	box := Box{Type: typ, Offset: offset, Length: size}
	payload := data[header:size]

	if typ != boxSuper {
		box.Payload = payload
		return box, size, true
	}

	children := p.boxes(payload, offset+header, depth+1)
	if len(children) > 0 && children[0].Type == boxDescription {
		box.Label, box.UUID = describe(children[0].Payload)
		children = children[1:]
	}
	box.Children = children
	return box, size, true
}

// describe reads a description box: the content type UUID, a toggle byte, and
// then whichever of the optional fields the toggles claim are present. The label
// is the field that matters here — it is how every part of a manifest is named.
func describe(payload []byte) (label string, uuid [16]byte) {
	if len(payload) < 17 {
		return "", uuid
	}
	copy(uuid[:], payload[:16])
	toggles := payload[16]
	at := 17
	if toggles&0x02 != 0 { // label present, NUL-terminated UTF-8
		end := bytes.IndexByte(payload[at:], 0)
		if end < 0 {
			return string(payload[at:]), uuid
		}
		label = string(payload[at : at+end])
	}
	return label, uuid
}

// contentType names a description box's UUID, for the labels C2PA gives its own
// box types. Unknown UUIDs report as hex, because a box type nobody recognises is
// itself worth seeing.
func contentType(uuid [16]byte) string {
	switch fmt.Sprintf("%X", uuid) {
	case "6332706100110010800000AA00389B71":
		return "manifest store"
	case "63326D6100110010800000AA00389B71":
		return "manifest"
	case "6332756D00110010800000AA00389B71":
		return "update manifest"
	case "6332636D00110010800000AA00389B71":
		return "compressed manifest"
	case "6332617300110010800000AA00389B71":
		return "assertion store"
	case "6332636C00110010800000AA00389B71":
		return "claim"
	case "6332637300110010800000AA00389B71":
		return "signature"
	case "6332646200110010800000AA00389B71":
		return "data boxes"
	case "6332766300110010800000AA00389B71":
		return "credentials store"
	}
	return fmt.Sprintf("%X", uuid)
}
