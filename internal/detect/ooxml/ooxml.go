// Package ooxml reads word-processor documents — .docx, .xlsx, .pptx and the
// OpenDocument formats — which are zip archives of XML wearing a file extension.
//
// The reason they are worth a handler is that they are where documents actually
// live, and every mechanism this tool was built to find has an equivalent inside
// one: text marked hidden and left in the file, text set to the colour of the
// page, the name of whoever last saved it, the edits that were made and then
// rejected, and whatever was stapled to the end of the archive.
//
// Nothing here is removable. Taking a run out of a document means rewriting XML
// and recompressing an archive, and what comes out is a different file with the
// same contents rather than the same file with something removed — which is not
// the promise this tool makes. See docs/decisions/lossless-only.md.
package ooxml

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/dejo1307/augur/internal/detect/c2pa"
	"github.com/dejo1307/augur/pkg/detect"
	"github.com/dejo1307/augur/pkg/finding"
)

// Kinds emitted by this detector.
const (
	KindProperties    = finding.Kind("office-properties")
	KindHiddenText    = finding.Kind("office-hidden-text")
	KindWhiteText     = finding.Kind("office-white-text")
	KindTrackedChange = finding.Kind("office-tracked-change")
	KindComment       = finding.Kind("office-comment")
	KindTrailing      = finding.Kind("office-trailing-bytes")
	KindC2PA          = c2pa.KindManifest
)

// Container is the detector for what a document carries besides its text.
type Container struct{}

func (Container) Name() string { return "office" }

func (Container) Applies(f detect.Format) bool { return f == detect.Office }

func (d Container) Detect(src *detect.Source) (finding.Set, error) {
	entries, err := read(src.Bytes)
	if err != nil {
		return nil, err
	}

	var out finding.Set
	out = append(out, d.credential(src.Bytes)...)
	out = append(out, d.properties(entries)...)
	out = append(out, d.hiddenRuns(entries)...)
	out = append(out, d.revisions(entries)...)
	out = append(out, d.trailing(src.Bytes)...)
	return out, nil
}

const irremovable = "Not removed: the document is a compressed archive of XML, so taking this out " +
	"means rebuilding the archive rather than editing the file, and this tool only removes what it " +
	"can remove exactly."

// ---------------------------------------------------------------------------
// findings
// ---------------------------------------------------------------------------

// propertyTags are the metadata fields worth naming, across both format families.
var propertyTags = []struct {
	tag       string
	label     string
	sensitive bool
}{
	{"dc:creator", "author", true},
	{"cp:lastModifiedBy", "last saved by", true},
	{"dc:title", "title", false},
	{"dc:subject", "subject", false},
	{"dc:description", "description", false},
	{"cp:keywords", "keywords", false},
	{"cp:revision", "revision number", false},
	{"dcterms:created", "created", false},
	{"dcterms:modified", "modified", false},
	{"Application", "produced by", false},
	{"AppVersion", "application version", false},
	{"Company", "company", true},
	{"Manager", "manager", true},
	{"Template", "template", false},
	{"TotalTime", "editing time (minutes)", false},
	{"meta:generator", "produced by", false},
	{"meta:initial-creator", "author", true},
	{"meta:editing-cycles", "times saved", false},
}

// credential reports a Content Credential carried by the archive.
//
// A zip-based document keeps one as a stored (uncompressed) part at
// META-INF/content_credential.c2pa. Its hard binding is a collection hash over
// every other part and the central directory, which is a different computation
// from the byte-range hash augur checks — so the credential is read and reported,
// and the binding is named rather than checked.
func (d Container) credential(data []byte) finding.Set {
	name, at, store, ok := credentialPart(data)
	if !ok {
		return nil
	}
	report := c2pa.Read(store, nil)

	label := fmt.Sprintf("C2PA Content Credential in %s (%d bytes)", name, len(store))
	severity := finding.Notice
	if summary := report.Summary(); summary != "" {
		label += " — " + summary
	}
	if report.Err != nil {
		severity = finding.Concern
		label = fmt.Sprintf("%s does not parse as a manifest store (%d bytes)", name, len(store))
	}

	return finding.Set{
		finding.New(d.Name(), KindC2PA, finding.Provenance, severity,
			finding.Span{Offset: at, Length: len(store), Exact: true}, label,
			"A signed record of where this document came from and what was done to it, kept as "+
				"a part of the archive. Nothing in the document's text shows it.").
			WithDetail(finding.NewTable("c2pa", report.Rows())).
			Irremovable(irremovable),
	}
}

// credentialPart finds the manifest store inside the archive.
//
// The specification names one location, and the name is matched rather than
// searched for — but the bytes are checked as well, because a part can be called
// anything and augur reports what a thing is rather than what it is labelled.
func credentialPart(data []byte) (name string, at int, store []byte, ok bool) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", 0, nil, false
	}
	for _, f := range zr.File {
		named := strings.EqualFold(f.Name, "META-INF/content_credential.c2pa") ||
			strings.HasSuffix(strings.ToLower(f.Name), ".c2pa")
		if !named || f.UncompressedSize64 > maxPart {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(rc, maxPart))
		_ = rc.Close()
		if err != nil || !c2pa.StoreMagic(body) {
			continue
		}
		off, err := f.DataOffset()
		if err != nil {
			off = 0
		}
		return f.Name, int(off), c2pa.TrimStore(body), true
	}
	return "", 0, nil, false
}

func (d Container) properties(entries []entry) finding.Set {
	var rows []finding.KV
	at := 0
	for _, e := range entries {
		if !isPropertyPart(e.name) {
			continue
		}
		if at == 0 {
			at = e.at
		}
		s := string(e.data)
		for _, p := range propertyTags {
			v := stripTags(between(s, "<"+p.tag, "</"+p.tag+">"))
			if v == "" {
				continue
			}
			rows = append(rows, finding.KV{Key: p.label, Value: truncate(v, 200), Sensitive: p.sensitive})
		}
	}
	if len(rows) == 0 {
		return nil
	}

	sev := finding.Notice
	for _, r := range rows {
		if r.Sensitive {
			sev = finding.Concern
		}
	}
	return finding.Set{finding.New(d.Name(), KindProperties, finding.Metadata, sev,
		finding.Span{Offset: at, Length: 0},
		fmt.Sprintf("document properties, %d field(s)", len(rows)),
		"The document's record of who wrote it, who last saved it, how long it was open and "+
			"what produced it. It is written automatically, it is not shown on any page, and it "+
			"survives every copy and every export that keeps the format.").
		WithDetail(finding.NewTable("office:properties", rows)).
		Irremovable(irremovable)}
}

func (d Container) hiddenRuns(entries []entry) finding.Set {
	var out finding.Set
	for _, e := range entries {
		if !strings.HasSuffix(e.name, ".xml") {
			continue
		}
		for _, r := range hiddenRunsIn(string(e.data)) {
			kind, cat, sev := KindHiddenText, finding.Invisible, finding.Alarm
			if r.how == whiteText {
				kind = KindWhiteText
			}
			out = append(out, finding.New(d.Name(), kind, cat, sev,
				finding.Span{Offset: e.at, Length: 0, Region: "office:" + e.name},
				fmt.Sprintf("%s: %q", r.how, truncate(r.text, 60)),
				"Text that is in the document and not on the page. It comes back the moment "+
					"the formatting is changed, it is read in full by anything that reads the "+
					"file, and a reader of the printed document has no way to know it is there.").
				WithDetail(finding.NewTable("office:hidden-text", []finding.KV{
					{Key: "part", Value: e.name},
					{Key: "how", Value: r.how},
					{Key: "text", Value: truncate(r.text, 400), Sensitive: true},
				})).
				Irremovable(irremovable))
		}
	}
	return out
}

func (d Container) revisions(entries []entry) finding.Set {
	var out finding.Set
	for _, e := range entries {
		s := string(e.data)

		if isCommentPart(e.name) {
			if text := stripTags(s); strings.TrimSpace(text) != "" {
				out = append(out, finding.New(d.Name(), KindComment, finding.Metadata, finding.Concern,
					finding.Span{Offset: e.at, Length: 0, Region: "office:" + e.name},
					fmt.Sprintf("review comments: %q", truncate(text, 60)),
					"Comments left on the document. They are part of the file rather than part "+
						"of the page, and they are commonly forgotten before it is sent on.").
					WithDetail(finding.NewTable("office:comments", []finding.KV{
						{Key: "part", Value: e.name},
						{Key: "text", Value: truncate(text, 400), Sensitive: true},
					})).
					Irremovable(irremovable))
			}
			continue
		}

		if !strings.HasSuffix(e.name, ".xml") {
			continue
		}
		ins, del := countTag(s, "<w:ins "), deletedText(s)
		if ins == 0 && del == "" {
			continue
		}
		label := fmt.Sprintf("tracked changes: %d insertion(s)", ins)
		if del != "" {
			label = fmt.Sprintf("tracked changes: %d insertion(s), deleted text %q", ins, truncate(del, 40))
		}
		out = append(out, finding.New(d.Name(), KindTrackedChange, finding.Metadata, finding.Concern,
			finding.Span{Offset: e.at, Length: 0, Region: "office:" + e.name},
			label,
			"The document records its own edit history. Text shown as deleted is still in the "+
				"file, and a reader who turns revision marks off sees the final wording while "+
				"the earlier wording travels with it.").
			WithDetail(finding.NewTable("office:tracked-changes", []finding.KV{
				{Key: "part", Value: e.name},
				{Key: "insertions", Value: fmt.Sprintf("%d", ins)},
				{Key: "deleted text", Value: truncate(del, 400), Sensitive: del != ""},
			})).
			Irremovable(irremovable))
	}
	return out
}

// trailing reports bytes after the archive's own end.
//
// A zip is read from its end-of-central-directory record backwards, so anything
// after it is invisible to every tool that opens the document and travels with it
// anyway — the same trick as bytes stapled past the end of a JPEG.
func (d Container) trailing(data []byte) finding.Set {
	at := bytes.LastIndex(data, []byte("PK\x05\x06"))
	if at < 0 || at+22 > len(data) {
		return nil
	}
	commentLen := int(data[at+20]) | int(data[at+21])<<8
	end := at + 22 + commentLen
	if end >= len(data) {
		return nil
	}

	extra := data[end:]
	return finding.Set{finding.New(d.Name(), KindTrailing, finding.Payload, finding.Alarm,
		finding.Span{Offset: end, Length: len(extra), Exact: true},
		fmt.Sprintf("%d bytes after the end of the archive", len(extra)),
		"The archive's directory says the file ended before these bytes. Every reader stops "+
			"there, so this is space that travels inside the document without being part of it.").
		WithDetail(finding.NewBlob(len(extra), preview(extra, 64), sniff(extra))).
		Irremovable(irremovable)}
}

// ---------------------------------------------------------------------------
// hidden runs
// ---------------------------------------------------------------------------

const whiteText = "text is the colour of the page"

type hiddenRun struct {
	how  string
	text string
}

// hiddenRunsIn finds the runs of a WordprocessingML part that are marked not to
// be shown, and the runs coloured to match the paper.
//
// Split on run boundaries rather than parsed as a tree, because that is all the
// structure the question needs: in this format a run carries its own properties,
// so a run marked hidden and the text it hides are always in the same element.
func hiddenRunsIn(s string) []hiddenRun {
	if !strings.Contains(s, "<w:r>") && !strings.Contains(s, "<w:r ") {
		return nil
	}

	var out []hiddenRun
	for _, run := range splitRuns(s) {
		props := between(run, "<w:rPr", "</w:rPr>")
		if props == "" {
			continue
		}
		text := strings.TrimSpace(runText(run))
		if text == "" {
			continue
		}

		switch {
		case hasEnabled(props, "<w:vanish"):
			out = append(out, hiddenRun{how: "marked hidden in the document's formatting", text: text})
		// nolint:misspell // "color" is WordprocessingML's own attribute name.
		case strings.Contains(props, `<w:color w:val="FFFFFF"`),
			strings.Contains(props, `<w:color w:val="ffffff"`):
			out = append(out, hiddenRun{how: whiteText, text: text})
		}
	}
	return out
}

func splitRuns(s string) []string {
	var out []string
	for i := 0; i < len(s); {
		start := indexAny(s[i:], "<w:r>", "<w:r ")
		if start < 0 {
			break
		}
		start += i
		end := strings.Index(s[start:], "</w:r>")
		if end < 0 {
			break
		}
		out = append(out, s[start:start+end])
		i = start + end + len("</w:r>")
	}
	return out
}

// hasEnabled reports whether a property is present and not explicitly switched
// off. `<w:vanish w:val="0"/>` is how a style says *not* hidden, and reading it as
// hidden would report every document that ever turned the setting off.
func hasEnabled(props, tag string) bool {
	i := strings.Index(props, tag)
	if i < 0 {
		return false
	}
	rest := props[i+len(tag):]
	if end := strings.IndexByte(rest, '>'); end >= 0 {
		attrs := rest[:end]
		if strings.Contains(attrs, `w:val="0"`) || strings.Contains(attrs, `w:val="false"`) {
			return false
		}
	}
	return true
}

// runText is the visible text of a run: its <w:t> elements, in order.
func runText(run string) string {
	var b strings.Builder
	for i := 0; i < len(run); {
		start := indexAny(run[i:], "<w:t>", "<w:t ")
		if start < 0 {
			break
		}
		start += i
		open := strings.IndexByte(run[start:], '>')
		if open < 0 {
			break
		}
		from := start + open + 1
		end := strings.Index(run[from:], "</w:t>")
		if end < 0 {
			break
		}
		b.WriteString(unescapeXML(run[from : from+end]))
		i = from + end + len("</w:t>")
	}
	return b.String()
}

// deletedText is the wording a tracked deletion removed, which is still in the file.
func deletedText(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		start := strings.Index(s[i:], "<w:delText")
		if start < 0 {
			break
		}
		start += i
		open := strings.IndexByte(s[start:], '>')
		if open < 0 {
			break
		}
		from := start + open + 1
		end := strings.Index(s[from:], "</w:delText>")
		if end < 0 {
			break
		}
		b.WriteString(unescapeXML(s[from : from+end]))
		b.WriteString(" ")
		i = from + end
	}
	return strings.TrimSpace(b.String())
}

// ---------------------------------------------------------------------------
// the archive
// ---------------------------------------------------------------------------

// entry is one part of the document, decompressed.
type entry struct {
	name string
	at   int // offset of the entry's local header, so a finding can point at it
	data []byte
}

const (
	maxPart  = 8 << 20  // one part
	maxTotal = 64 << 20 // all of them together
)

// read decompresses the parts of the document that hold text.
//
// Bounded twice, per part and in total, because a zip is a format in which a few
// kilobytes can claim to be a few gigabytes, and this tool is routinely pointed at
// files precisely because they are not trusted.
func read(data []byte) ([]entry, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("not a readable archive: %w", err)
	}

	total := 0
	var out []entry
	for _, f := range zr.File {
		if !isTextPart(f.Name) || f.UncompressedSize64 > maxPart || total >= maxTotal {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue // one unreadable part does not make the document unscannable
		}
		body, err := io.ReadAll(io.LimitReader(rc, maxPart))
		_ = rc.Close()
		if err != nil {
			continue
		}
		off, err := f.DataOffset()
		if err != nil {
			off = 0
		}
		total += len(body)
		out = append(out, entry{name: f.Name, at: int(off), data: body})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out, nil
}

func isTextPart(name string) bool {
	for _, suffix := range []string{".xml", ".rels", ".txt", ".json", ".htm", ".html", ".csv"} {
		if strings.HasSuffix(strings.ToLower(name), suffix) {
			return true
		}
	}
	return name == "mimetype"
}

func isPropertyPart(name string) bool {
	return name == "docProps/core.xml" || name == "docProps/app.xml" ||
		name == "docProps/custom.xml" || name == "meta.xml"
}

func isCommentPart(name string) bool {
	return name == "word/comments.xml" || name == "xl/comments1.xml" ||
		strings.HasPrefix(name, "ppt/notesSlides/")
}

// Regions exposes every text part of the document, so the detectors that read a
// .txt file read the inside of a .docx unchanged.
//
// Derived, never inline: the parts are deflated, so the text handed out here does
// not exist anywhere in the file in this form and no finding in it can address
// file bytes. That is what the Exact flag is for, and leaving it false is what
// keeps a finding in a document from claiming it can be removed.
func Regions(data []byte) []detect.Region {
	entries, err := read(data)
	if err != nil {
		return nil
	}
	out := make([]detect.Region, 0, len(entries))
	for _, e := range entries {
		if len(e.data) == 0 {
			continue
		}
		out = append(out, detect.Region{
			Name:   "office:" + e.name,
			Offset: e.at,
			Text:   string(e.data),
		})
	}
	return out
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func indexAny(s string, subs ...string) int {
	best := -1
	for _, sub := range subs {
		if i := strings.Index(s, sub); i >= 0 && (best < 0 || i < best) {
			best = i
		}
	}
	return best
}

// between returns the content of an element. `open` is the element name with its
// leading angle bracket and *without* the closing one — `<dc:creator` — so that an
// element carrying attributes is matched as readily as one that does not.
func between(s, open, closing string) string {
	i := strings.Index(s, open)
	if i < 0 {
		return ""
	}
	rest := s[i+len(open):]
	gt := strings.IndexByte(rest, '>')
	if gt < 0 {
		return ""
	}
	rest = rest[gt+1:]
	j := strings.Index(rest, closing)
	if j < 0 {
		return ""
	}
	return rest[:j]
}

func countTag(s, tag string) int {
	return strings.Count(s, tag)
}

func stripTags(s string) string {
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
	return strings.TrimSpace(unescapeXML(b.String()))
}

func unescapeXML(s string) string {
	return strings.NewReplacer(
		"&amp;", "&", "&lt;", "<", "&gt;", ">", "&quot;", `"`, "&apos;", "'",
	).Replace(s)
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
		{"%PDF", "PDF document"}, {"MZ", "Windows executable"},
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
