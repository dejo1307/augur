package image

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/dejo1307/augur/pkg/finding"
)

// This is a deliberately small TIFF/IFD reader rather than a dependency.
//
// The job is narrow: name the tags a person would want to decide about, and read
// their values well enough to show them. A full EXIF library reads hundreds of
// maker-specific tags, and none of that changes what the user is choosing — they
// are choosing whether the block goes or stays. What matters is that the tags that
// identify a person or a place are shown by name and marked, and that is a short
// list that does not churn.

type byteOrder = binary.ByteOrder

// tagNames covers the tags worth naming. Anything else is shown as its number,
// which is honest: the block is still reported, it is just not editorialised.
var tagNames = map[uint16]string{
	0x010E: "ImageDescription",
	0x010F: "Make",
	0x0110: "Model",
	0x0112: "Orientation",
	0x0131: "Software",
	0x0132: "DateTime",
	0x013B: "Artist",
	0x8298: "Copyright",
	0x9003: "DateTimeOriginal",
	0x9004: "DateTimeDigitized",
	0x927C: "MakerNote",
	0x9286: "UserComment",
	0xA430: "CameraOwnerName",
	0xA431: "BodySerialNumber",
	0xA432: "LensSpecification",
	0xA433: "LensMake",
	0xA434: "LensModel",
	0xA435: "LensSerialNumber",
	0xC614: "UniqueCameraModel",
	0xA420: "ImageUniqueID",
}

var gpsTagNames = map[uint16]string{
	0x0001: "GPSLatitudeRef",
	0x0002: "GPSLatitude",
	0x0003: "GPSLongitudeRef",
	0x0004: "GPSLongitude",
	0x0005: "GPSAltitudeRef",
	0x0006: "GPSAltitude",
	0x0007: "GPSTimeStamp",
	0x0012: "GPSMapDatum",
	0x001D: "GPSDateStamp",
}

// sensitive marks the tags that identify a person, a device, or a place. These are
// highlighted, because "there is EXIF here" and "there is a home address here" are
// very different sentences and the tool should not make the user work out which
// one it means.
var sensitive = map[string]bool{
	"GPSLatitude": true, "GPSLongitude": true, "GPSAltitude": true,
	"GPSTimeStamp": true, "GPSDateStamp": true, "GPSMapDatum": true,
	"Artist": true, "Copyright": true, "CameraOwnerName": true,
	"BodySerialNumber": true, "LensSerialNumber": true, "ImageUniqueID": true,
	"UserComment": true, "MakerNote": true,
}

// exifRows decodes a TIFF block into displayable rows. `tiff` must start at the
// TIFF header (the "II"/"MM" bytes), not at the "Exif\0\0" preamble.
func exifRows(tiff []byte) []finding.KV {
	if len(tiff) < 8 {
		return nil
	}
	var ord byteOrder
	switch string(tiff[0:2]) {
	case "II":
		ord = binary.LittleEndian
	case "MM":
		ord = binary.BigEndian
	default:
		return nil
	}
	if ord.Uint16(tiff[2:4]) != 42 {
		return nil
	}

	var rows []finding.KV
	seen := map[int]bool{} // IFD offsets already walked, so a cyclic file terminates

	var walk func(off int, names map[uint16]string, depth int)
	walk = func(off int, names map[uint16]string, depth int) {
		if depth > 4 || off <= 0 || off+2 > len(tiff) || seen[off] {
			return
		}
		seen[off] = true

		count := int(ord.Uint16(tiff[off : off+2]))
		base := off + 2
		if base+count*12 > len(tiff) {
			return
		}
		for i := 0; i < count; i++ {
			e := tiff[base+i*12 : base+i*12+12]
			tag := ord.Uint16(e[0:2])
			typ := ord.Uint16(e[2:4])
			n := int(ord.Uint32(e[4:8]))

			// Sub-IFD pointers: the Exif and GPS blocks hang off IFD0.
			switch tag {
			case 0x8769:
				walk(int(ord.Uint32(e[8:12])), tagNames, depth+1)
				continue
			case 0x8825:
				walk(int(ord.Uint32(e[8:12])), gpsTagNames, depth+1)
				continue
			}

			name, known := names[tag]
			if !known {
				if n, ok := tagNames[tag]; ok {
					name, known = n, true
				}
			}
			if !known {
				continue // reported as part of the block, just not named individually
			}
			val := tagValue(tiff, ord, typ, n, e[8:12])
			if val == "" {
				continue
			}
			rows = append(rows, finding.KV{Key: name, Value: val, Sensitive: sensitive[name]})
		}
		next := base + count*12
		if next+4 <= len(tiff) {
			walk(int(ord.Uint32(tiff[next:next+4])), names, depth+1)
		}
	}

	walk(int(ord.Uint32(tiff[4:8])), tagNames, 0)
	return append(rows, derivedPosition(rows)...)
}

// derivedPosition turns the GPS tags into one line a person can read.
//
// "52/1, 31/1, 1200/100" is technically the answer and practically useless; the
// decision the user is making is whether the file says where they were, and
// "52.5200 N, 13.4050 E" is that sentence. The raw tags stay in the table beside
// it — this adds a reading, it does not replace the evidence.
func derivedPosition(rows []finding.KV) []finding.KV {
	get := func(k string) string {
		for _, r := range rows {
			if r.Key == k {
				return r.Value
			}
		}
		return ""
	}
	lat, latRef := get("GPSLatitude"), get("GPSLatitudeRef")
	lon, lonRef := get("GPSLongitude"), get("GPSLongitudeRef")
	if lat == "" || lon == "" {
		return nil
	}
	latDeg, ok1 := dms(lat)
	lonDeg, ok2 := dms(lon)
	if !ok1 || !ok2 {
		return nil
	}
	if latRef == "" {
		latRef = "N"
	}
	if lonRef == "" {
		lonRef = "E"
	}
	return []finding.KV{{
		Key:       "position",
		Value:     fmt.Sprintf("%.4f %s, %.4f %s", latDeg, latRef, lonDeg, lonRef),
		Sensitive: true,
	}}
}

// dms parses the "degrees, minutes, seconds" triple EXIF stores coordinates as.
func dms(s string) (float64, bool) {
	parts := strings.Split(s, ", ")
	if len(parts) != 3 {
		return 0, false
	}
	var v [3]float64
	for i, p := range parts {
		f, err := strconv.ParseFloat(strings.TrimSpace(p), 64)
		if err != nil {
			return 0, false
		}
		v[i] = f
	}
	return v[0] + v[1]/60 + v[2]/3600, true
}

// typeSize is the byte width of each TIFF field type, indexed by type code.
var typeSize = map[uint16]int{1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8}

// tagValue renders one field. Values of four bytes or fewer sit inline; anything
// larger is at an offset into the TIFF block.
func tagValue(tiff []byte, ord byteOrder, typ uint16, count int, inline []byte) string {
	size, ok := typeSize[typ]
	if !ok || count <= 0 {
		return ""
	}
	total := size * count
	data := inline
	if total > 4 {
		off := int(ord.Uint32(inline))
		if off < 0 || off+total > len(tiff) {
			return ""
		}
		data = tiff[off : off+total]
	} else {
		data = inline[:total]
	}

	switch typ {
	case 2: // ASCII
		return strings.TrimRight(string(data), "\x00 ")
	case 1, 7: // BYTE / UNDEFINED
		if count > 24 {
			return fmt.Sprintf("<%d bytes>", count)
		}
		return strings.TrimRight(string(data), "\x00 ")
	case 3: // SHORT
		var parts []string
		for i := 0; i+2 <= len(data) && i < 8*2; i += 2 {
			parts = append(parts, fmt.Sprint(ord.Uint16(data[i:i+2])))
		}
		return strings.Join(parts, ", ")
	case 4: // LONG
		var parts []string
		for i := 0; i+4 <= len(data) && i < 8*4; i += 4 {
			parts = append(parts, fmt.Sprint(ord.Uint32(data[i:i+4])))
		}
		return strings.Join(parts, ", ")
	case 5, 10: // RATIONAL
		var parts []string
		for i := 0; i+8 <= len(data); i += 8 {
			num, den := ord.Uint32(data[i:i+4]), ord.Uint32(data[i+4:i+8])
			if den == 0 {
				parts = append(parts, "0")
				continue
			}
			parts = append(parts, trimFloat(float64(num)/float64(den)))
		}
		return strings.Join(parts, ", ")
	}
	return ""
}

func trimFloat(f float64) string {
	s := fmt.Sprintf("%.6f", f)
	s = strings.TrimRight(s, "0")
	return strings.TrimRight(s, ".")
}
