package c2pa

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"strings"
)

// Where a manifest store sits differs per format, and every one of those places
// is somebody's convention rather than a thing you can sniff for. The functions
// here hold the parts of that knowledge that are C2PA's rather than the
// container's: how a store is reassembled out of JPEG segments, and how it is
// spelled inside an SVG. Finding the segments and the elements is the format
// handler's job; knowing what to do with them once found is this package's.

// StoreMagic reports whether these bytes open a C2PA manifest store: a JUMBF
// superbox whose description box is labelled "c2pa".
//
// This is a positive identification rather than a substring search. A file
// mentioning "c2pa" somewhere in a comment is not carrying a credential, and a
// tool that reports one because the letters appear is a tool nobody can rely on.
func StoreMagic(b []byte) bool {
	if len(b) < 12 {
		return false
	}
	if string(b[4:8]) != boxSuper {
		return false
	}
	// The superbox's first child is its description box, whose content type UUID
	// begins with the four bytes "c2pa" for a manifest store.
	if len(b) < 32 || string(b[12:16]) != boxDescription {
		return false
	}
	return string(b[16:20]) == "c2pa"
}

// TrimStore cuts a manifest store down to the length its own box header declares.
//
// A carrier hands over slightly more than the store on occasion — a PDF stream
// keeps the end-of-line byte before its "endstream" keyword — and those extra
// bytes matter twice: the box reader reports the store as truncated when it tries
// to read them as another box, and the extent handed to the binding check is a
// byte longer than the range the claim excluded, which fails the check for a file
// that is perfectly intact.
func TrimStore(b []byte) []byte {
	if len(b) < 8 {
		return b
	}
	declared := int(binary.BigEndian.Uint32(b[0:4]))
	if declared >= 8 && declared < len(b) {
		return b[:declared]
	}
	return b
}

// jpegSegmentHeader is the fixed part of an APP11 segment's payload: the two-byte
// common identifier "JP", a two-byte box instance number, and a four-byte packet
// sequence number.
const jpegSegmentHeader = 8

// JoinJPEGSegments reassembles a manifest store from the APP11 segments carrying
// it, in file order.
//
// A JPEG segment holds at most 64 KB and a manifest store is routinely larger, so
// the store is split across several. The first segment carries the JUMBF box
// header; every continuation repeats that header and must have it stripped, or the
// reassembled store is interleaved with eight bytes of framing every 64 KB and
// nothing parses.
//
// Segments are grouped by box instance number: two unrelated APP11 users in one
// file each get their own, and joining across them would splice two structures
// together.
// It returns the store and the indices of the payloads it was built from, because
// only the first segment of a store is identifiable on its own. A continuation
// carries eight bytes of repeated framing and then raw manifest bytes — nothing in
// it says "C2PA" — so a caller that classifies segments one at a time reports the
// first as a credential and the rest as unknown application segments. Which
// segments belong to the store is a question only reassembly can answer, and this
// is where it gets answered.
func JoinJPEGSegments(payloads [][]byte) (store []byte, used []int) {
	var instance []byte
	started := false

	for i, p := range payloads {
		if len(p) <= jpegSegmentHeader || string(p[0:2]) != "JP" {
			continue
		}
		en := p[2:4]
		body := p[jpegSegmentHeader:]

		if started && bytes.Equal(instance, en) {
			// A continuation repeats LBox and TBox before its share of the store.
			if len(body) <= 8 {
				continue
			}
			store = append(store, body[8:]...)
			used = append(used, i)
			continue
		}
		if !started && StoreMagic(body) {
			store = append(store, body...)
			used = append(used, i)
			instance = append([]byte(nil), en...)
			started = true
		}
	}
	return store, used
}

// FixJPEGStoreLength rewrites the reassembled store's outer length field.
//
// The first segment's LBox describes the whole store, which is what we want — but
// a store split across segments and then rejoined can disagree with it by the
// framing bytes that were stripped. The box reader refuses a box claiming more
// bytes than are present, correctly, so the length is corrected to the bytes
// actually recovered rather than the reader being taught to trust a length it
// cannot check.
func FixJPEGStoreLength(store []byte) []byte {
	if len(store) < 8 {
		return store
	}
	declared := binary.BigEndian.Uint32(store[0:4])
	if declared == uint32(len(store)) {
		return store
	}
	out := make([]byte, len(store))
	copy(out, store)
	binary.BigEndian.PutUint32(out[0:4], uint32(len(out)))
	return out
}

// SVGManifest is a Content Credential found in an SVG document.
type SVGManifest struct {
	// Offset and Length locate the whole <c2pa:manifest> element in the file, so
	// removing the credential is deleting exactly those bytes.
	Offset, Length int
	// Payload locates the base64 text inside the element. It is a separate extent
	// from the element because it is the one the claim excludes from its hash: the
	// tags around it are hashed like the rest of the document.
	Payload Extent
	// Store is the decoded manifest store.
	Store []byte
}

// InSVG finds a manifest in an SVG document. C2PA writes it as base64 inside a
// <c2pa:manifest> element within <metadata>, so unlike every other carrier here
// it is text — which means a text-shaped removal takes it out exactly, and the
// text detectors have already read whatever else is in the document.
func InSVG(data []byte) (SVGManifest, bool) {
	const open = "<c2pa:manifest"
	start := bytes.Index(data, []byte(open))
	if start < 0 {
		return SVGManifest{}, false
	}
	// The element's own tag may carry the namespace declaration, so find the end
	// of the opening tag rather than assuming its length.
	tagEnd := bytes.IndexByte(data[start:], '>')
	if tagEnd < 0 {
		return SVGManifest{}, false
	}
	tagEnd += start + 1

	closeAt := bytes.Index(data[tagEnd:], []byte("</c2pa:manifest>"))
	if closeAt < 0 {
		return SVGManifest{}, false
	}
	body := data[tagEnd : tagEnd+closeAt]
	end := tagEnd + closeAt + len("</c2pa:manifest>")

	m := SVGManifest{
		Offset:  start,
		Length:  end - start,
		Payload: Extent{Offset: tagEnd, Length: len(body)},
	}
	// XML permits whitespace inside the element that is not part of the payload.
	encoded := strings.Join(strings.Fields(string(body)), "")
	store, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		// Not the encoding the specification requires, so this is not a
		// credential — most likely something quoting the element rather than
		// carrying one. Reporting it would put a finding on every file that
		// discusses the format, including this repository's own source.
		return SVGManifest{}, false
	}
	m.Store = store
	return m, true
}
