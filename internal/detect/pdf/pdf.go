// Package pdf reads a PDF the way the image package reads a JPEG: as a container
// with compartments, some of which hold things nobody typed into the document.
//
// It is not a renderer and does not try to be. It parses far enough to answer the
// questions this tool asks — what metadata is in here, what text is in here that
// the page does not show, what is stapled to the end — and stops. Everything it
// cannot answer is left to the blind-spots panel rather than guessed at.
//
// Nothing here is removable. A PDF's cross-reference table records the byte offset
// of every object in the file, so removing anything shifts offsets the table still
// points at, and the honest way to take something out of a PDF is to rewrite the
// document. This package therefore reports and explains, and says plainly that it
// will not edit. See docs/decisions/lossless-only.md.
package pdf

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/dejo1307/augur/pkg/detect"
	"github.com/dejo1307/augur/pkg/finding"
)

// Kinds emitted by this detector.
const (
	KindInfo          = finding.Kind("pdf-info")
	KindXMP           = finding.Kind("pdf-xmp")
	KindJavaScript    = finding.Kind("pdf-javascript")
	KindEmbeddedFile  = finding.Kind("pdf-embedded-file")
	KindInvisibleText = finding.Kind("pdf-invisible-text")
	KindIncremental   = finding.Kind("pdf-incremental-update")
	KindTrailing      = finding.Kind("pdf-trailing-bytes")
)

// Container is the detector for what a PDF carries besides its pages.
type Container struct{}

func (Container) Name() string { return "pdf" }

func (Container) Applies(f detect.Format) bool { return f == detect.PDF }

func (d Container) Detect(src *detect.Source) (finding.Set, error) {
	doc := parse(src.Bytes)

	var out finding.Set
	out = append(out, d.metadata(doc)...)
	out = append(out, d.actions(doc)...)
	out = append(out, d.invisibleText(doc)...)
	out = append(out, d.structure(doc, src.Bytes)...)
	return out, nil
}

// ---------------------------------------------------------------------------
// findings
// ---------------------------------------------------------------------------

func (d Container) metadata(doc document) finding.Set {
	var out finding.Set
	for _, o := range doc.objects {
		if rows := infoRows(o.dict); len(rows) > 0 {
			out = append(out, finding.New(d.Name(), KindInfo, finding.Metadata, severityOfInfo(rows),
				finding.Span{Offset: o.at, Length: o.length, Exact: true},
				fmt.Sprintf("document information, %d field(s)", len(rows)),
				"The document's own record of who made it and with what. It is written by the "+
					"producing application, travels with every copy, and is not shown anywhere "+
					"in the page.").
				WithDetail(finding.NewTable("pdf:info", rows)).
				Irremovable(irremovable))
			continue
		}

		if isXMP(o) {
			out = append(out, finding.New(d.Name(), KindXMP, finding.Metadata, finding.Notice,
				finding.Span{Offset: o.at, Length: o.length, Exact: true},
				fmt.Sprintf("XMP metadata (%d bytes)", len(o.stream)),
				"An XML metadata packet. Editors record authorship, edit history and rights "+
					"here, and generators record which tool produced the file.").
				WithDetail(finding.NewTable("pdf:xmp", xmpRows(o.stream))).
				Irremovable(irremovable))
		}
	}
	return out
}

func (d Container) actions(doc document) finding.Set {
	var out finding.Set
	for _, o := range doc.objects {
		switch {
		case containsAny(o.dict, "/JavaScript", "/JS"):
			out = append(out, finding.New(d.Name(), KindJavaScript, finding.Payload, finding.Alarm,
				finding.Span{Offset: o.at, Length: o.length, Exact: true},
				"JavaScript embedded in the document",
				"A PDF can carry code and ask the reader to run it, including on open. Nothing "+
					"about the page says so.").
				WithDetail(finding.NewBlob(o.length, preview([]byte(o.dict), 200), "pdf object")).
				Irremovable(irremovable))

		case containsAny(o.dict, "/EmbeddedFile", "/Filespec"):
			out = append(out, finding.New(d.Name(), KindEmbeddedFile, finding.Payload, finding.Concern,
				finding.Span{Offset: o.at, Length: o.length, Exact: true},
				fmt.Sprintf("embedded file attachment (%d bytes)", len(o.stream)),
				"A whole file carried inside the document. It travels with it through copies "+
					"and forwards, and most readers give no sign that it is there.").
				WithDetail(finding.NewBlob(len(o.stream), preview(o.stream, 64), sniff(o.stream))).
				Irremovable(irremovable))
		}
	}
	return out
}

// invisibleText reports text the page draws and does not show.
//
// The PDF imaging model has a text rendering mode that marks glyphs as neither
// filled nor stroked: mode 3, `3 Tr`. The text is positioned, selectable,
// copyable and searchable, and no ink is laid down for it. Every scanned document
// with an OCR layer uses it legitimately, which is exactly what makes it a good
// place to leave a sentence for whatever reads the file next.
func (d Container) invisibleText(doc document) finding.Set {
	var out finding.Set
	for _, o := range doc.objects {
		if len(o.stream) == 0 {
			continue
		}
		for _, hidden := range hiddenTextIn(o.stream) {
			label := fmt.Sprintf("invisible text (%s): %q", hidden.how, truncate(hidden.text, 60))
			out = append(out, finding.New(d.Name(), KindInvisibleText, finding.Invisible, finding.Alarm,
				finding.Span{Offset: o.at, Length: o.length, Exact: true},
				label,
				"Text drawn onto the page in a way that leaves no mark on it. It is in the "+
					"file, it comes out when the page is copied or read by a machine, and the "+
					"reader of the printed page has no way to know it was there.").
				WithDetail(finding.NewTable("pdf:invisible-text", []finding.KV{
					{Key: "how", Value: hidden.how},
					{Key: "text", Value: truncate(hidden.text, 400), Sensitive: true},
				})).
				Irremovable(irremovable))
		}
	}
	return out
}

func (d Container) structure(doc document, data []byte) finding.Set {
	var out finding.Set

	if doc.revisions > 1 {
		out = append(out, finding.New(d.Name(), KindIncremental, finding.Payload, finding.Concern,
			finding.Span{Offset: doc.firstEOF, Length: 0, Exact: true},
			fmt.Sprintf("%d document revisions in one file", doc.revisions),
			"This PDF was saved incrementally: each edit was appended and the previous version "+
				"was left in place underneath. Text that was deleted or covered over in a later "+
				"revision is still in the file, and readers show only the last one.").
			WithDetail(finding.NewTable("pdf:revisions", []finding.KV{
				{Key: "revisions", Value: fmt.Sprintf("%d", doc.revisions)},
				{Key: "note", Value: "earlier revisions retain content edited out of the current one", Sensitive: true},
			})).
			Irremovable(irremovable))
	}

	if doc.trailing > 0 && doc.trailing < len(data) {
		extra := data[doc.trailing:]
		out = append(out, finding.New(d.Name(), KindTrailing, finding.Payload, finding.Alarm,
			finding.Span{Offset: doc.trailing, Length: len(extra), Exact: true},
			fmt.Sprintf("%d bytes after the end of the document", len(extra)),
			"The file says it ended before these bytes. Readers stop at the marker, so this is "+
				"space that travels with the document without being part of it.").
			WithDetail(finding.NewBlob(len(extra), preview(extra, 64), sniff(extra))).
			Irremovable(irremovable))
	}
	return out
}

const irremovable = "Not removed: a PDF records the byte offset of every object in a table, so taking " +
	"anything out means rewriting the document rather than editing it, and this tool only removes " +
	"what it can remove exactly."

// ---------------------------------------------------------------------------
// text regions
// ---------------------------------------------------------------------------

// Regions exposes the text a PDF carries so that the text detectors read it — the
// same arrangement as image metadata, and the reason a zero-width payload inside a
// PDF's title is found by the code that reads a .txt file.
//
// Every region here is derived rather than inline. A PDF string is escaped, often
// compressed, and frequently UTF-16: the text these detectors see never appears in
// the file in the form they see it, so no finding in it can claim a byte range.
// Saying that plainly is the contract, and it is why none of this is removable.
func Regions(data []byte) []detect.Region {
	doc := parse(data)
	var out []detect.Region
	for _, o := range doc.objects {
		if isXMP(o) && len(o.stream) > 0 {
			out = append(out, detect.Region{
				Name: fmt.Sprintf("pdf:xmp[%d]", o.num), Offset: o.at, Text: string(o.stream),
			})
			continue
		}
		if rows := infoRows(o.dict); len(rows) > 0 {
			var b strings.Builder
			for _, r := range rows {
				fmt.Fprintf(&b, "%s: %s\n", r.Key, r.Value)
			}
			out = append(out, detect.Region{
				Name: fmt.Sprintf("pdf:info[%d]", o.num), Offset: o.at, Text: b.String(),
			})
			continue
		}
		if text := contentText(o.stream); text != "" {
			out = append(out, detect.Region{
				Name: fmt.Sprintf("pdf:text[%d]", o.num), Offset: o.at, Text: text,
			})
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// parsing
// ---------------------------------------------------------------------------

type object struct {
	num    int
	at     int // offset of the object header in the file
	length int
	dict   string // the object's dictionary, as written
	stream []byte // the object's stream, decompressed where possible
}

type document struct {
	objects   []object
	revisions int // how many times the file says it ends
	firstEOF  int
	trailing  int // offset just past the last end-of-file marker, or 0
}

// maxStream bounds what this will inflate from one object. A compression bomb in
// a file this tool was pointed at is a denial of service against the person who
// pointed it, and no legitimate metadata stream is anywhere near this size.
const maxStream = 16 << 20

func parse(data []byte) document {
	doc := document{}

	// Object headers: "12 0 obj". Found by scanning for the keyword and reading
	// backwards, because the generation and object numbers precede it.
	for i := 0; i+3 <= len(data); {
		k := bytes.Index(data[i:], []byte("obj"))
		if k < 0 {
			break
		}
		k += i
		i = k + 3

		num, start, ok := objectHeader(data, k)
		if !ok {
			continue
		}
		end := objectEnd(data, i)
		o := object{num: num, at: start, length: end - start}
		o.dict, o.stream = dictAndStream(data[i:end])
		doc.objects = append(doc.objects, o)
		i = end
	}

	// Revisions and trailing bytes both come off the end-of-file markers.
	for at := 0; ; {
		k := bytes.Index(data[at:], []byte("%%EOF"))
		if k < 0 {
			break
		}
		k += at
		if doc.revisions == 0 {
			doc.firstEOF = k
		}
		doc.revisions++
		at = k + 5
		doc.trailing = at
	}
	// A trailing newline after the final marker is the file ending tidily, not
	// something hidden behind it.
	for doc.trailing < len(data) && (data[doc.trailing] == '\n' || data[doc.trailing] == '\r') {
		doc.trailing++
	}
	if doc.trailing >= len(data) {
		doc.trailing = 0
	}
	return doc
}

// objectHeader reads the "12 0" before an "obj" keyword and returns the object
// number and where the header starts.
func objectHeader(data []byte, at int) (num, start int, ok bool) {
	i := at
	i = skipBackSpace(data, i)
	genEnd := i
	i = skipBackDigits(data, i)
	if i == genEnd {
		return 0, 0, false
	}
	i = skipBackSpace(data, i)
	numEnd := i
	i = skipBackDigits(data, i)
	if i == numEnd {
		return 0, 0, false
	}
	n := 0
	for _, c := range data[i:numEnd] {
		n = n*10 + int(c-'0')
		if n > 1<<30 {
			return 0, 0, false
		}
	}
	return n, i, true
}

func skipBackSpace(data []byte, i int) int {
	for i > 0 && (data[i-1] == ' ' || data[i-1] == '\r' || data[i-1] == '\n' || data[i-1] == '\t') {
		i--
	}
	return i
}

func skipBackDigits(data []byte, i int) int {
	for i > 0 && data[i-1] >= '0' && data[i-1] <= '9' {
		i--
	}
	return i
}

// objectEnd finds where an object stops: at its endobj, or at the start of the
// next one if the file is malformed enough to be missing it.
func objectEnd(data []byte, from int) int {
	end := bytes.Index(data[from:], []byte("endobj"))
	if end < 0 {
		return len(data)
	}
	return from + end + 6
}

// dictAndStream splits an object's body into its dictionary and its stream,
// inflating the stream when it is deflated.
func dictAndStream(body []byte) (string, []byte) {
	k := bytes.Index(body, []byte("stream"))
	if k < 0 {
		return string(body), nil
	}
	dict := string(body[:k])

	raw := body[k+len("stream"):]
	raw = bytes.TrimLeft(raw, "\r\n")
	if end := bytes.Index(raw, []byte("endstream")); end >= 0 {
		raw = raw[:end]
	}
	if len(raw) > maxStream {
		raw = raw[:maxStream]
	}

	if strings.Contains(dict, "/FlateDecode") {
		if out, err := inflate(raw); err == nil {
			return dict, out
		}
		// A stream that will not inflate is reported through whatever else the
		// object says about itself rather than treated as an error: a detector
		// that fails on one malformed object would report the whole file as
		// unscanned.
		return dict, nil
	}
	return dict, raw
}

func inflate(raw []byte) ([]byte, error) {
	zr, err := zlib.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	defer func() { _ = zr.Close() }()
	return io.ReadAll(io.LimitReader(zr, maxStream))
}

func isXMP(o object) bool {
	return strings.Contains(o.dict, "/Metadata") && strings.Contains(o.dict, "/XML") ||
		bytes.Contains(o.stream, []byte("<x:xmpmeta"))
}

// ---------------------------------------------------------------------------
// dictionaries and content streams
// ---------------------------------------------------------------------------

// infoKeys are the document information fields. Listed rather than taken from
// whatever the dictionary happens to contain, so that a page object with a /Title
// is not reported as document metadata.
var infoKeys = []string{
	"Title", "Author", "Subject", "Keywords", "Creator", "Producer",
	"CreationDate", "ModDate", "Company", "SourceModified",
}

func infoRows(dict string) []finding.KV {
	var rows []finding.KV
	for _, key := range infoKeys {
		v, ok := dictString(dict, "/"+key)
		if !ok || v == "" {
			continue
		}
		rows = append(rows, finding.KV{
			Key:       key,
			Value:     truncate(v, 200),
			Sensitive: key == "Author" || key == "Company",
		})
	}
	// One field alone is usually a coincidence in some other object; the info
	// dictionary always carries several.
	if len(rows) < 2 {
		return nil
	}
	return rows
}

func severityOfInfo(rows []finding.KV) finding.Severity {
	for _, r := range rows {
		if r.Sensitive {
			return finding.Concern
		}
	}
	return finding.Notice
}

// dictString reads a string value out of a dictionary: `/Author (Jane Doe)` or
// `/Author <FEFF004A...>`.
func dictString(dict, key string) (string, bool) {
	i := strings.Index(dict, key)
	if i < 0 {
		return "", false
	}
	rest := strings.TrimLeft(dict[i+len(key):], " \t\r\n")
	switch {
	case strings.HasPrefix(rest, "("):
		s, _, ok := literalString(rest, 0)
		return s, ok
	case strings.HasPrefix(rest, "<") && !strings.HasPrefix(rest, "<<"):
		end := strings.IndexByte(rest, '>')
		if end < 0 {
			return "", false
		}
		return decodeText(hexBytes(rest[1:end])), true
	}
	return "", false
}

// literalString reads a PDF literal string starting at i, honouring escapes and
// nested parentheses.
func literalString(s string, i int) (string, int, bool) {
	if i >= len(s) || s[i] != '(' {
		return "", i, false
	}
	var b []byte
	depth := 1
	for j := i + 1; j < len(s); j++ {
		c := s[j]
		switch c {
		case '\\':
			if j+1 < len(s) {
				j++
				switch s[j] {
				case 'n':
					b = append(b, '\n')
				case 'r':
					b = append(b, '\r')
				case 't':
					b = append(b, '\t')
				default:
					b = append(b, s[j])
				}
			}
		case '(':
			depth++
			b = append(b, c)
		case ')':
			depth--
			if depth == 0 {
				return decodeText(b), j + 1, true
			}
			b = append(b, c)
		default:
			b = append(b, c)
		}
	}
	return "", i, false
}

func hexBytes(s string) []byte {
	var out []byte
	var cur byte
	half := false
	for _, c := range s {
		var v byte
		switch {
		case c >= '0' && c <= '9':
			v = byte(c - '0')
		case c >= 'a' && c <= 'f':
			v = byte(c-'a') + 10
		case c >= 'A' && c <= 'F':
			v = byte(c-'A') + 10
		default:
			continue
		}
		if half {
			out = append(out, cur<<4|v)
			half = false
			continue
		}
		cur = v
		half = true
	}
	if half {
		out = append(out, cur<<4)
	}
	return out
}

// decodeText renders a PDF string as UTF-8. PDF text strings are either
// UTF-16BE behind a byte-order mark or PDFDocEncoding, which agrees with Latin-1
// closely enough for the purpose of showing someone what their file says.
func decodeText(b []byte) string {
	if len(b) >= 2 && b[0] == 0xFE && b[1] == 0xFF {
		u := make([]uint16, 0, (len(b)-2)/2)
		for i := 2; i+1 < len(b); i += 2 {
			u = append(u, uint16(b[i])<<8|uint16(b[i+1]))
		}
		return string(utf16.Decode(u))
	}
	if utf8.Valid(b) {
		return string(b)
	}
	var sb strings.Builder
	for _, c := range b {
		sb.WriteRune(rune(c))
	}
	return sb.String()
}

// hiddenText is one stretch of text a content stream draws invisibly.
type hiddenText struct {
	how  string
	text string
}

// hiddenTextIn walks a content stream tracking the two pieces of graphics state
// that decide whether text leaves a mark: the rendering mode and the fill colour.
//
// This is a reader of the operators that matter and not an interpreter of the
// page. It carries no coordinates, no fonts and no clipping, so it will not find
// text hidden by being drawn underneath an image or off the edge of the page —
// which is stated in the blind-spots panel rather than approximated here.
func hiddenTextIn(stream []byte) []hiddenText {
	if !bytes.Contains(stream, []byte("Tj")) && !bytes.Contains(stream, []byte("TJ")) {
		return nil
	}

	var out []hiddenText
	var operands []string
	mode := 0
	white := false
	var pending []string

	flush := func(how string) {
		if len(pending) == 0 {
			return
		}
		text := strings.TrimSpace(strings.Join(pending, ""))
		pending = nil
		if text == "" {
			return
		}
		out = append(out, hiddenText{how: how, text: text})
	}

	// A content stream is postfix: operands accumulate until an operator consumes
	// them. Anything that is not an operator is an operand, which is the only way
	// to read `3 Tr` — the 3 arrives before there is any reason to care about it.
	for _, tok := range tokenize(string(stream)) {
		if tok.isString || isOperand(tok.text) {
			operands = append(operands, tok.text)
			continue
		}
		switch tok.text {
		case "Tr":
			if len(operands) > 0 {
				mode = atoi(operands[len(operands)-1])
			}
		case "rg", "g", "sc", "scn":
			white = allOnes(operands)
		case "Tj", "TJ", "'", `"`:
			if mode == 3 || white {
				pending = append(pending, operands...)
			}
		case "ET":
			if mode == 3 {
				flush("render mode 3 — drawn without ink")
			} else if white {
				flush("filled with white — the colour of the page")
			}
			mode, white = 0, false
		}
		operands = operands[:0]
	}
	if mode == 3 {
		flush("render mode 3 — drawn without ink")
	} else if white {
		flush("filled with white — the colour of the page")
	}
	return out
}

type token struct {
	text     string
	isString bool
}

// tokenize splits a content stream into strings and everything else. Only the two
// categories matter here: what would be drawn, and what decides how.
func tokenize(s string) []token {
	var out []token
	for i := 0; i < len(s); {
		switch c := s[i]; {
		case c == '(':
			text, next, ok := literalString(s, i)
			if !ok {
				i++
				continue
			}
			out = append(out, token{text: text, isString: true})
			i = next
		case c == '<' && i+1 < len(s) && s[i+1] != '<':
			end := strings.IndexByte(s[i:], '>')
			if end < 0 {
				i++
				continue
			}
			out = append(out, token{text: decodeText(hexBytes(s[i+1 : i+end])), isString: true})
			i += end + 1
		case c == ' ' || c == '\n' || c == '\r' || c == '\t' || c == '[' || c == ']':
			i++
		default:
			j := i
			for j < len(s) && !strings.ContainsRune(" \n\r\t[]<>()", rune(s[j])) {
				j++
			}
			if j == i {
				i++
				continue
			}
			out = append(out, token{text: s[i:j]})
			i = j
		}
	}
	return out
}

// contentText is everything a content stream would draw, for the text detectors
// to read. Drawn or not: a hidden character is worth finding wherever it is.
func contentText(stream []byte) string {
	if len(stream) == 0 || !utf8.Valid(stream) && !bytes.Contains(stream, []byte("Tj")) {
		return ""
	}
	var parts []string
	for _, tok := range tokenize(string(stream)) {
		if tok.isString && strings.TrimSpace(tok.text) != "" {
			parts = append(parts, tok.text)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " ")
}

// isOperand reports whether a token is a value rather than an operator: a number,
// or a name like /F1. Operators in this format are always keywords.
func isOperand(tok string) bool {
	if tok == "" {
		return false
	}
	c := tok[0]
	return c == '/' || c == '-' || c == '+' || c == '.' || c >= '0' && c <= '9'
}

func allOnes(operands []string) bool {
	if len(operands) == 0 {
		return false
	}
	for _, o := range operands {
		if o != "1" && o != "1.0" && o != "1.00" {
			return false
		}
	}
	return true
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return -1
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func xmpRows(packet []byte) []finding.KV {
	s := string(packet)
	var rows []finding.KV
	for _, tag := range []string{
		"dc:title", "dc:creator", "dc:description", "dc:rights",
		"xmp:CreatorTool", "xmp:CreateDate", "xmp:ModifyDate",
		"pdf:Producer", "photoshop:AuthorsPosition",
	} {
		if v := between(s, "<"+tag+">", "</"+tag+">"); v != "" {
			rows = append(rows, finding.KV{
				Key:       tag,
				Value:     truncate(stripXMLTags(v), 200),
				Sensitive: strings.Contains(tag, "creator") || strings.Contains(tag, "Author"),
			})
		}
	}
	if len(rows) == 0 {
		rows = append(rows, finding.KV{Key: "packet", Value: truncate(s, 200)})
	}
	return rows
}

func between(s, open, close string) string {
	i := strings.Index(s, open)
	if i < 0 {
		return ""
	}
	rest := s[i+len(open):]
	j := strings.Index(rest, close)
	if j < 0 {
		return ""
	}
	return rest[:j]
}

func stripXMLTags(s string) string {
	var b strings.Builder
	depth := 0
	for _, r := range s {
		switch r {
		case '<':
			depth++
		case '>':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 {
				b.WriteRune(r)
			}
		}
	}
	return strings.TrimSpace(b.String())
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func preview(b []byte, n int) []byte {
	if len(b) > n {
		return b[:n]
	}
	return b
}

func sniff(b []byte) string {
	for _, m := range []struct{ magic, name string }{
		{"PK\x03\x04", "zip archive"}, {"\x89PNG", "PNG image"}, {"\xFF\xD8\xFF", "JPEG image"},
		{"%PDF", "PDF document"}, {"\x7FELF", "ELF executable"}, {"MZ", "Windows executable"},
	} {
		if bytes.HasPrefix(b, []byte(m.magic)) {
			return m.name
		}
	}
	return ""
}

func truncate(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
