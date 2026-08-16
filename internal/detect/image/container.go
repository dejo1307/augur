// Package image reads what an image file carries besides its picture: the
// metadata blocks, the provenance manifests, and anything sitting in space the
// format does not account for.
//
// It walks containers and never decodes pixels. That is not a shortcut — it is the
// decision in docs/decisions/lossless-only.md expressed as code. A walker that
// never looks at pixel data cannot accidentally re-encode them, and a rewrite that
// copies the compressed scan through byte-for-byte is lossless by construction
// rather than by care.
package image

import (
	"encoding/binary"
	"fmt"
)

// Block is one addressable piece of a container: a JPEG segment, a PNG chunk, a
// RIFF chunk. The walkers reduce three quite different formats to this, so the
// detector and the cleaner are written once.
type Block struct {
	// Kind is the format's own name for it: "APP1", "COM", "tEXt", "EXIF".
	Kind string
	// Offset and Length cover the WHOLE block including its header and length
	// field, because that is the unit a rewrite drops or keeps.
	Offset int
	Length int
	// Payload is the block's contents without its framing, as a slice of the
	// original bytes. PayloadOffset locates it, so a finding inside the payload
	// still has a true file offset.
	Payload       []byte
	PayloadOffset int
	// Essential marks a block the image cannot survive without. A cleaner must
	// never drop one, whatever the user selected.
	Essential bool
}

// Walk splits a container into blocks. It returns the blocks it understood plus
// any trailing bytes, and an error only when the file is not the format claimed.
type Walk struct {
	Blocks []Block
	// Trailing is data after the container's logical end. Never part of the
	// image; always worth reporting.
	Trailing []byte
	// TrailingOffset locates it.
	TrailingOffset int
}

// WalkJPEG marches the segment list. A JPEG is a sequence of marker segments
// ending at the start-of-scan, after which the entropy-coded data runs to the
// end-of-image marker.
func WalkJPEG(data []byte) (Walk, error) {
	var w Walk
	if len(data) < 4 || data[0] != 0xFF || data[1] != 0xD8 {
		return w, fmt.Errorf("not a JPEG")
	}
	// SOI itself.
	w.Blocks = append(w.Blocks, Block{Kind: "SOI", Offset: 0, Length: 2, Essential: true})

	i := 2
	for i+1 < len(data) {
		if data[i] != 0xFF {
			// Marker padding is legal; anything else means the structure is lost
			// and guessing past it would risk a rewrite that corrupts the image.
			i++
			continue
		}
		marker := data[i+1]
		if marker == 0xFF {
			i++
			continue
		}
		// Standalone markers carry no length.
		if marker == 0xD8 || (marker >= 0xD0 && marker <= 0xD9) || marker == 0x01 {
			w.Blocks = append(w.Blocks, Block{
				Kind: markerName(marker), Offset: i, Length: 2, Essential: true,
			})
			i += 2
			continue
		}
		if i+4 > len(data) {
			break
		}
		size := int(binary.BigEndian.Uint16(data[i+2 : i+4]))
		if size < 2 || i+2+size > len(data) {
			break
		}
		payload := data[i+4 : i+2+size]
		b := Block{
			Kind:          markerName(marker),
			Offset:        i,
			Length:        2 + size,
			Payload:       payload,
			PayloadOffset: i + 4,
			Essential:     essentialJPEG(marker, payload),
		}
		w.Blocks = append(w.Blocks, b)
		i += 2 + size

		// Start of scan: the compressed image follows, up to EOI. Everything from
		// here is picture, and this package does not read pictures.
		if marker == 0xDA {
			end := findEOI(data, i)
			w.Blocks = append(w.Blocks, Block{
				Kind: "scan", Offset: i, Length: end - i, Essential: true,
			})
			if end < len(data) {
				w.Trailing = data[end:]
				w.TrailingOffset = end
			}
			return w, nil
		}
	}
	return w, nil
}

// findEOI returns the offset just past the end-of-image marker, or len(data).
func findEOI(data []byte, from int) int {
	for i := from; i+1 < len(data); i++ {
		if data[i] == 0xFF && data[i+1] == 0xD9 {
			return i + 2
		}
	}
	return len(data)
}

func markerName(m byte) string {
	switch {
	case m >= 0xE0 && m <= 0xEF:
		return fmt.Sprintf("APP%d", m-0xE0)
	case m == 0xFE:
		return "COM"
	case m == 0xDB:
		return "DQT"
	case m == 0xC4:
		return "DHT"
	case m == 0xDA:
		return "SOS"
	case m == 0xD9:
		return "EOI"
	case m == 0xD8:
		return "SOI"
	case m >= 0xC0 && m <= 0xCF:
		return "SOF"
	default:
		return fmt.Sprintf("FF%02X", m)
	}
}

// essentialJPEG reports whether dropping a marker would break the image. The APPn
// and COM segments carry metadata; everything else is structure.
//
// The exception is APP0/JFIF, which is structure wearing an APPn marker: it
// declares the pixel density and thumbnail layout that make the file a JFIF rather
// than a bare JPEG. It is also present in almost every JPEG ever written, so
// reporting it as an unrecognised segment would put one line of noise at the top
// of nearly every scan — and a finding a user learns to skip past costs more than
// it is worth.
func essentialJPEG(m byte, payload []byte) bool {
	if m == 0xE0 && (hasPrefix(payload, "JFIF\x00") || hasPrefix(payload, "JFXX\x00")) {
		return true
	}
	if m >= 0xE0 && m <= 0xEF {
		return false // APPn: metadata
	}
	if m == 0xFE {
		return false // COM: a comment
	}
	return true
}

func hasPrefix(b []byte, s string) bool {
	return len(b) >= len(s) && string(b[:len(s)]) == s
}

// WalkPNG walks the chunk list. A PNG is a signature followed by length-tagged,
// CRC-terminated chunks.
func WalkPNG(data []byte) (Walk, error) {
	var w Walk
	const sig = "\x89PNG\r\n\x1a\n"
	if len(data) < len(sig) || string(data[:len(sig)]) != sig {
		return w, fmt.Errorf("not a PNG")
	}
	w.Blocks = append(w.Blocks, Block{Kind: "signature", Offset: 0, Length: len(sig), Essential: true})

	i := len(sig)
	for i+8 <= len(data) {
		size := int(binary.BigEndian.Uint32(data[i : i+4]))
		if size < 0 || i+12+size > len(data) {
			break
		}
		kind := string(data[i+4 : i+8])
		w.Blocks = append(w.Blocks, Block{
			Kind:          kind,
			Offset:        i,
			Length:        12 + size, // length + type + data + CRC
			Payload:       data[i+8 : i+8+size],
			PayloadOffset: i + 8,
			Essential:     essentialPNG(kind),
		})
		i += 12 + size
		if kind == "IEND" {
			if i < len(data) {
				w.Trailing = data[i:]
				w.TrailingOffset = i
			}
			return w, nil
		}
	}
	return w, nil
}

// essentialPNG keeps the critical chunks and anything affecting how pixels are
// interpreted. A PNG chunk is critical when its first letter is upper case, which
// is exactly what that bit of the spec is for — so this reads the rule rather than
// listing names and going stale.
func essentialPNG(kind string) bool {
	if len(kind) != 4 {
		return true
	}
	if kind[0] >= 'A' && kind[0] <= 'Z' {
		return true // critical chunk
	}
	switch kind {
	case "tRNS", "gAMA", "cHRM", "sRGB", "sBIT", "bKGD", "pHYs", "acTL", "fcTL", "fdAT":
		return true // ancillary, but changes how the image renders
	}
	return false
}

// WalkWebP walks the RIFF chunk list.
func WalkWebP(data []byte) (Walk, error) {
	var w Walk
	if len(data) < 12 || string(data[0:4]) != "RIFF" || string(data[8:12]) != "WEBP" {
		return w, fmt.Errorf("not a WebP")
	}
	w.Blocks = append(w.Blocks, Block{Kind: "RIFF", Offset: 0, Length: 12, Essential: true})

	riffSize := int(binary.LittleEndian.Uint32(data[4:8]))
	end := 8 + riffSize
	if end > len(data) {
		end = len(data)
	}

	i := 12
	for i+8 <= end {
		kind := string(data[i : i+4])
		size := int(binary.LittleEndian.Uint32(data[i+4 : i+8]))
		total := 8 + size
		if size%2 == 1 {
			total++ // RIFF chunks are padded to an even length
		}
		if i+total > end {
			break
		}
		w.Blocks = append(w.Blocks, Block{
			Kind:          kind,
			Offset:        i,
			Length:        total,
			Payload:       data[i+8 : i+8+size],
			PayloadOffset: i + 8,
			Essential:     essentialWebP(kind),
		})
		i += total
	}
	if i < len(data) {
		w.Trailing = data[i:]
		w.TrailingOffset = i
	}
	return w, nil
}

func essentialWebP(kind string) bool {
	switch kind {
	case "EXIF", "XMP ", "ICCP":
		return false
	}
	return true
}
