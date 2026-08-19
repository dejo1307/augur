package image

import (
	"bytes"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/dejo1307/augur/internal/detect/c2pa"
	"github.com/dejo1307/augur/pkg/detect"
	"github.com/dejo1307/augur/pkg/finding"
)

// Kinds emitted by this detector.
const (
	KindEXIF       = finding.Kind("exif")
	KindXMP        = finding.Kind("xmp")
	KindIPTC       = finding.Kind("iptc")
	KindICC        = finding.Kind("icc-profile")
	KindComment    = finding.Kind("comment")
	KindPNGText    = finding.Kind("png-text")
	KindC2PA       = finding.Kind("c2pa-manifest")
	KindC2PABroken = finding.Kind("c2pa-binding-mismatch")
	KindTrailing   = finding.Kind("trailing-bytes")
	KindUnknownApp = finding.Kind("unknown-segment")
)

// Container is the detector for image metadata, provenance and stowaway bytes.
type Container struct{}

func (Container) Name() string { return "container" }

func (Container) Applies(f detect.Format) bool {
	switch f {
	case detect.JPEG, detect.PNG, detect.WebP:
		return true
	}
	return false
}

// walk dispatches to the right container walker.
func walk(data []byte, f detect.Format) (Walk, error) {
	switch f {
	case detect.JPEG:
		return WalkJPEG(data)
	case detect.PNG:
		return WalkPNG(data)
	case detect.WebP:
		return WalkWebP(data)
	}
	return Walk{}, fmt.Errorf("no walker for %s", f)
}

func (d Container) Detect(src *detect.Source) (finding.Set, error) {
	w, err := walk(src.Bytes, src.Format)
	if err != nil {
		return nil, err
	}

	// A Content Credential is the one thing here that is not read block by block:
	// a manifest store larger than a JPEG segment is split across several, and
	// what it says can only be read once they are back together.
	credential, store, rest := splitCredential(w.Blocks, src.Format)

	var out finding.Set
	for _, b := range rest {
		if f, ok := d.describe(b, src.Format); ok {
			out = append(out, f)
		}
	}
	out = append(out, d.credential(credential, store, src)...)

	if len(w.Trailing) > 0 {
		out = append(out, finding.New(d.Name(), KindTrailing, finding.Payload, finding.Alarm,
			finding.Span{Offset: w.TrailingOffset, Length: len(w.Trailing), Exact: true},
			fmt.Sprintf("%d bytes after the end of the image", len(w.Trailing)),
			"The image format says the file ended before these bytes. Viewers ignore them, so "+
				"they are a place to keep something that travels with the picture without "+
				"appearing in it.").
			WithDetail(finding.NewBlob(len(w.Trailing), preview(w.Trailing, 64), sniffBytes(w.Trailing))).
			Deletable())
	}
	return out, nil
}

// describe turns one non-essential block into a finding.
func (d Container) describe(b Block, format detect.Format) (finding.Finding, bool) {
	span := finding.Span{Offset: b.Offset, Length: b.Length, Exact: true}
	mk := func(kind finding.Kind, cat finding.Category, sev finding.Severity, label, why string) finding.Finding {
		return finding.New(d.Name(), kind, cat, sev, span, label, why).Deletable()
	}

	switch {
	case isEXIF(b, format):
		rows := exifRows(exifTIFF(b, format))
		sev := finding.Notice
		for _, r := range rows {
			if r.Sensitive {
				sev = finding.Concern
			}
		}
		return mk(KindEXIF, finding.Metadata, sev,
			exifLabel(b, rows),
			"Camera and capture data recorded when the image was made. It travels with the "+
				"file through copies and uploads unless something strips it.",
		).WithDetail(finding.NewTable("exif", rows)), true

	case isXMP(b, format):
		return mk(KindXMP, finding.Metadata, finding.Notice,
			fmt.Sprintf("XMP metadata (%s)", humanBytes(b.Length)),
			"An XML metadata block. Editors use it for authorship, edit history and rights, "+
				"and generators use it to record which tool produced the file.",
		).WithDetail(finding.NewTable("xmp", xmpRows(b.Payload))), true

	case isIPTC(b, format):
		return mk(KindIPTC, finding.Metadata, finding.Notice,
			fmt.Sprintf("IPTC / Photoshop resource block (%s)", humanBytes(b.Length)),
			"Publishing metadata: captions, credits, keywords and location names, written by "+
				"photo editors and news systems.",
		), true

	case isICC(b, format):
		return mk(KindICC, finding.Metadata, finding.Notice,
			fmt.Sprintf("ICC colour profile (%s)", humanBytes(b.Length)),
			"Describes how the image's colours should be interpreted. Removing it is safe for "+
				"the file but can shift how colours appear on a wide-gamut display.",
		), true

	case format == detect.JPEG && b.Kind == "COM":
		text := string(b.Payload)
		return mk(KindComment, finding.Metadata, finding.Notice,
			fmt.Sprintf("JPEG comment: %q", truncate(text, 48)),
			"A free-text comment stored in the file. Nothing shows it, so it is a convenient "+
				"place to leave a note or a marker.",
		).WithDetail(finding.NewTable("comment", []finding.KV{{Key: "text", Value: text}})), true

	case format == detect.PNG && isPNGText(b.Kind):
		key, val := pngText(b)
		return mk(KindPNGText, finding.Metadata, finding.Notice,
			fmt.Sprintf("PNG %s chunk: %s", b.Kind, key),
			"A text field stored in the image. Generators commonly record the prompt, the "+
				"model and the settings here, and nothing displays it.",
		).WithDetail(finding.NewTable("png:"+b.Kind, []finding.KV{{Key: key, Value: truncate(val, 400)}})), true

	case format == detect.JPEG && strings.HasPrefix(b.Kind, "APP"):
		return mk(KindUnknownApp, finding.Metadata, finding.Notice,
			fmt.Sprintf("%s segment, %s, purpose not recognised", b.Kind, humanBytes(b.Length)),
			"An application segment augur does not recognise. It is not part of the "+
				"picture, so something put it there on purpose.",
		).WithDetail(finding.NewBlob(len(b.Payload), preview(b.Payload, 48), sniffBytes(b.Payload))), true
	}
	return finding.Finding{}, false
}

// ---------------------------------------------------------------------------
// block identification
// ---------------------------------------------------------------------------

const (
	exifPrefix = "Exif\x00\x00"
	xmpPrefix  = "http://ns.adobe.com/xap/1.0/\x00"
	iptcPrefix = "Photoshop 3.0\x00"
	iccPrefix  = "ICC_PROFILE\x00"
)

func isEXIF(b Block, f detect.Format) bool {
	switch f {
	case detect.JPEG:
		return b.Kind == "APP1" && bytes.HasPrefix(b.Payload, []byte(exifPrefix))
	case detect.PNG:
		return b.Kind == "eXIf"
	case detect.WebP:
		return b.Kind == "EXIF"
	}
	return false
}

// exifTIFF returns the TIFF block inside an EXIF container, skipping whatever
// preamble the format puts in front of it.
func exifTIFF(b Block, f detect.Format) []byte {
	if f == detect.JPEG && bytes.HasPrefix(b.Payload, []byte(exifPrefix)) {
		return b.Payload[len(exifPrefix):]
	}
	return b.Payload
}

func isXMP(b Block, f detect.Format) bool {
	switch f {
	case detect.JPEG:
		return b.Kind == "APP1" && bytes.HasPrefix(b.Payload, []byte(xmpPrefix))
	case detect.WebP:
		return b.Kind == "XMP "
	case detect.PNG:
		return b.Kind == "iTXt" && bytes.Contains(b.Payload, []byte("XML:com.adobe.xmp"))
	}
	return false
}

func isIPTC(b Block, f detect.Format) bool {
	return f == detect.JPEG && b.Kind == "APP13" && bytes.HasPrefix(b.Payload, []byte(iptcPrefix))
}

func isICC(b Block, f detect.Format) bool {
	switch f {
	case detect.JPEG:
		return b.Kind == "APP2" && bytes.HasPrefix(b.Payload, []byte(iccPrefix))
	case detect.PNG:
		return b.Kind == "iCCP"
	case detect.WebP:
		return b.Kind == "ICCP"
	}
	return false
}

// isC2PA recognises a Content Credential. It rides in a JUMBF box, which is APP11
// in JPEG, the caBX chunk in PNG, and a RIFF chunk called C2PA in WebP.
//
// The WebP case is not a completeness exercise. Content Credentials are being
// attached to generated images today, WebP is one of the formats they are
// generated in, and a chunk augur walks past is a provenance manifest it reports
// as absent.
func isC2PA(b Block) bool {
	switch b.Kind {
	case "caBX", "C2PA":
		return true
	case "APP11":
		// JUMBF boxes carry a "jumb" type; the C2PA store labels itself. A
		// continuation segment repeats the same framing, which is why this
		// matches the later segments of a split store too.
		return bytes.Contains(b.Payload, []byte("jumb")) &&
			(bytes.Contains(b.Payload, []byte("c2pa")) || bytes.Contains(b.Payload, []byte("cai")))
	}
	return false
}

func isPNGText(kind string) bool {
	return kind == "tEXt" || kind == "iTXt" || kind == "zTXt"
}

// pngText splits a PNG text chunk into its keyword and value. zTXt values are
// compressed; rather than decompress them here, the keyword is reported and the
// value left described but unread — the block is removable either way, and
// claiming to have read something we did not would be the wrong kind of helpful.
func pngText(b Block) (string, string) {
	i := bytes.IndexByte(b.Payload, 0)
	if i < 0 {
		return string(b.Payload), ""
	}
	key := string(b.Payload[:i])
	rest := b.Payload[i+1:]
	switch b.Kind {
	case "tEXt":
		return key, string(rest)
	case "iTXt":
		// compression flag, compression method, language tag, translated keyword
		if len(rest) < 2 {
			return key, ""
		}
		if rest[0] != 0 {
			return key, "<compressed>"
		}
		parts := bytes.SplitN(rest[2:], []byte{0}, 3)
		if len(parts) == 3 {
			return key, string(parts[2])
		}
		return key, ""
	default: // zTXt
		return key, "<compressed>"
	}
}

// credential reads the Content Credential carried by these blocks and reports it.
//
// Two findings can come out of it. The manifest itself is one, reported neutrally
// and removable like any other metadata block. The other is the answer to the
// question a signed manifest invites and nothing else in a file can settle: does
// the file still match what was signed?
func (d Container) credential(blocks []Block, store []byte, src *detect.Source) finding.Set {
	if len(blocks) == 0 {
		return nil
	}

	extents := make([]c2pa.Extent, 0, len(blocks))
	total := 0
	for _, b := range blocks {
		extents = append(extents, c2pa.Extent{Offset: b.Offset, Length: b.Length})
		total += b.Length
	}
	report := c2pa.Read(store, src.Bytes, extents...)

	span := finding.Span{Offset: blocks[0].Offset, Length: blocks[0].Length, Exact: true}
	label := fmt.Sprintf("C2PA Content Credential (%s)", humanBytes(total))
	severity := finding.Notice
	if summary := report.Summary(); summary != "" {
		label += " — " + summary
	}
	if report.Err != nil {
		// A block that announces itself as a Content Credential and then will not
		// parse as one is not a credential; it is an opaque payload wearing the
		// label of something viewers skip.
		severity = finding.Concern
		label = fmt.Sprintf("C2PA block that does not parse as a manifest (%s)", humanBytes(total))
	}

	out := finding.Set{
		finding.New(d.Name(), KindC2PA, finding.Provenance, severity, span, label,
			"A signed record of where this image came from and what was done to it. It is "+
				"metadata like any other block here and can be removed — but unlike the rest, "+
				"removing it takes away evidence rather than exposure.",
		).WithDetail(finding.NewTable("c2pa", report.Rows())).Deletable(),
	}

	// The store's later segments are the same manifest continued. They are
	// reported so that removing the credential removes all of it — a JPEG left
	// holding segments two and three of a manifest whose first segment is gone
	// carries a fragment nothing can read.
	for i, b := range blocks[1:] {
		out = append(out, finding.New(d.Name(), KindC2PA, finding.Provenance, finding.Notice,
			finding.Span{Offset: b.Offset, Length: b.Length, Exact: true},
			fmt.Sprintf("C2PA Content Credential, continued (part %d of %d, %s)",
				i+2, len(blocks), humanBytes(b.Length)),
			"The rest of the manifest above. A manifest store larger than one segment is "+
				"split across several, and they are removed together or not at all.",
		).Deletable())
	}

	if report.Mismatched() {
		out = append(out, finding.New(d.Name(), KindC2PABroken, finding.Provenance, finding.Concern,
			span,
			"the Content Credential no longer matches this file",
			"The manifest carries a hash over the file's bytes, and they no longer hash to it. "+
				"The file was changed after it was signed — by an edit, a re-save, a metadata "+
				"strip, or anything else that rewrote a byte the claim covered. The credential "+
				"still describes the file it was made for; this is no longer that file.",
		).WithDetail(finding.NewTable("c2pa-binding", []finding.KV{
			{Key: "algorithm", Value: report.Binding.Alg},
			{Key: "claim says", Value: report.Binding.Expected},
			{Key: "file hashes to", Value: report.Binding.Actual, Sensitive: true},
		})).Irremovable("Nothing can be removed to fix this: the mismatch is a fact about the "+
			"file's history, not a block in it."))
	}
	return out
}

// splitCredential separates the blocks carrying a Content Credential from the
// rest, and recovers the manifest store they hold.
//
// PNG and WebP keep the whole store in one chunk, so the split is a test on each
// block. JPEG splits it across segments that each repeat eight bytes of framing
// and only the first of which is recognisable, so the reassembly decides which
// segments were part of it — and any APP11 that was not is handed back to be
// reported as the unknown segment it is.
func splitCredential(blocks []Block, format detect.Format) (credential []Block, store []byte, rest []Block) {
	if format == detect.JPEG {
		var app11 []Block
		var payloads [][]byte
		for _, b := range blocks {
			if b.Essential {
				continue
			}
			if b.Kind == "APP11" {
				app11 = append(app11, b)
				payloads = append(payloads, b.Payload)
				continue
			}
			rest = append(rest, b)
		}
		joined, used := c2pa.JoinJPEGSegments(payloads)
		inStore := make(map[int]bool, len(used))
		for _, i := range used {
			inStore[i] = true
		}
		for i, b := range app11 {
			if inStore[i] {
				credential = append(credential, b)
				continue
			}
			rest = append(rest, b)
		}
		return credential, c2pa.FixJPEGStoreLength(joined), rest
	}

	for _, b := range blocks {
		if b.Essential {
			continue
		}
		if len(credential) == 0 && isC2PA(b) {
			credential = append(credential, b)
			store = b.Payload
			continue
		}
		rest = append(rest, b)
	}
	return credential, store, rest
}

// xmpRows pulls the handful of XMP fields worth naming. A full XML parse is not
// warranted: the user is deciding about the block, not about a field.
func xmpRows(payload []byte) []finding.KV {
	s := string(payload)
	var rows []finding.KV
	for _, f := range []string{
		"xmp:CreatorTool", "tiff:Make", "tiff:Model", "dc:creator", "dc:rights",
		"photoshop:Credit", "xmpMM:DocumentID", "xmpMM:InstanceID", "GPano:",
	} {
		if i := strings.Index(s, f); i >= 0 {
			rows = append(rows, finding.KV{
				Key:       strings.TrimSuffix(f, ":"),
				Value:     truncate(strings.TrimSpace(fieldAfter(s[i:], f)), 80),
				Sensitive: strings.Contains(f, "creator") || strings.Contains(f, "GPano"),
			})
		}
	}
	if len(rows) == 0 {
		rows = append(rows, finding.KV{Key: "size", Value: humanBytes(len(payload))})
	}
	return rows
}

func fieldAfter(s, field string) string {
	s = strings.TrimPrefix(s, field)
	s = strings.TrimLeft(s, "=\"> ")
	for i, r := range s {
		if r == '<' || r == '"' || r == '\n' {
			return s[:i]
		}
	}
	return truncate(s, 80)
}

func exifLabel(b Block, rows []finding.KV) string {
	for _, r := range rows {
		if r.Key == "GPSLatitude" {
			return fmt.Sprintf("EXIF with GPS coordinates (%s)", humanBytes(b.Length))
		}
	}
	return fmt.Sprintf("EXIF metadata, %d field(s) (%s)", len(rows), humanBytes(b.Length))
}

// ---------------------------------------------------------------------------
// text regions, so the text detectors read an image's metadata too
// ---------------------------------------------------------------------------

// Regions exposes the readable text an image carries, so the same detectors that
// find a hidden message in a .txt file find one in a JPEG's XMP packet. It falls
// straight out of the layering, and it is the reason the two detector families
// live behind one interface.
func Regions(data []byte, format detect.Format) []detect.Region {
	w, err := walk(data, format)
	if err != nil {
		return nil
	}
	var out []detect.Region
	for _, b := range w.Blocks {
		if b.Essential || len(b.Payload) == 0 {
			continue
		}
		switch {
		case isXMP(b, format):
			// The XMP packet is stored verbatim, so offsets are exact — but it is
			// inside a length-prefixed segment, so the text cleaner declines to
			// own it and the container cleaner drops the whole block instead.
			off, text := skipPrefix(b, xmpPrefix)
			out = append(out, detect.Region{Name: "xmp", Offset: off, Text: text, Exact: true})

		case format == detect.JPEG && b.Kind == "COM":
			out = append(out, detect.Region{
				Name: "comment", Offset: b.PayloadOffset, Text: string(b.Payload), Exact: true,
			})

		case format == detect.PNG && isPNGText(b.Kind):
			key, val := pngText(b)
			if val == "" || val == "<compressed>" {
				continue
			}
			// tEXt and uncompressed iTXt store the value verbatim; its offset is
			// the chunk payload plus the keyword and its terminator.
			off := b.PayloadOffset + len(b.Payload) - len(val)
			out = append(out, detect.Region{
				Name: "png:" + b.Kind + "[" + key + "]", Offset: off, Text: val, Exact: true,
			})
		}
	}
	return out
}

func skipPrefix(b Block, prefix string) (int, string) {
	if bytes.HasPrefix(b.Payload, []byte(prefix)) {
		return b.PayloadOffset + len(prefix), string(b.Payload[len(prefix):])
	}
	return b.PayloadOffset, string(b.Payload)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func preview(b []byte, n int) []byte {
	if len(b) > n {
		return b[:n]
	}
	return b
}

// sniffBytes names what a blob looks like, when it looks like anything. Bytes
// hidden past the end of an image are much more interesting when they are a zip.
func sniffBytes(b []byte) string {
	for _, m := range []struct{ magic, name string }{
		{"PK\x03\x04", "zip archive"},
		{"\x89PNG", "PNG image"},
		{"\xFF\xD8\xFF", "JPEG image"},
		{"%PDF", "PDF document"},
		{"GIF8", "GIF image"},
		{"\x7FELF", "ELF executable"},
		{"MZ", "Windows executable"},
		{"\x1F\x8B", "gzip data"},
		{"Rar!", "RAR archive"},
	} {
		if bytes.HasPrefix(b, []byte(m.magic)) {
			return m.name
		}
	}
	if utf8.Valid(b) && isMostlyPrintable(b) {
		return "text"
	}
	return ""
}

func isMostlyPrintable(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	good := 0
	for _, c := range b {
		if c >= 0x20 && c < 0x7F || c == '\n' || c == '\t' || c >= 0x80 {
			good++
		}
	}
	return good*10 >= len(b)*9
}

func humanBytes(n int) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f kB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
