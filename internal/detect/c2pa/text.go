package c2pa

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/dejo1307/augur/pkg/detect"
	"github.com/dejo1307/augur/pkg/finding"
)

// Content Credentials are not only an image thing any more. The specification
// defines three ways to put one in text, and every one of them lands in the kind
// of file augur was built for — a note, a README, a page, an instruction file a
// model reads on every session:
//
//   - unstructured text: the manifest encoded as Unicode variation selectors,
//     invisible, at the end of the content (spec A.8);
//   - structured text: an ASCII-armoured block in a comment or in front matter,
//     holding a data: URI or a URL (A.9);
//   - HTML: a <script type="application/c2pa"> element, or a <link> to a manifest
//     stored elsewhere (A.7).
//
// The first of those is the one that matters most here. augur already reports a
// run of variation selectors as a hidden payload and decodes it — so before this
// existed, a Content Credential in a paragraph of text came out as "hidden
// message, 12,000 characters" of unreadable bytes. It is not a hidden message. It
// is a signed statement about where the text came from, and it can say which model
// wrote it.

// KindReference is a credential the file points at rather than carries.
const KindReference = finding.Kind("c2pa-reference")

// Text finds Content Credentials in text documents.
type Text struct{}

func (Text) Name() string { return "c2pa-text" }

func (Text) Applies(f detect.Format) bool { return f == detect.Text }

func (d Text) Detect(src *detect.Source) (finding.Set, error) {
	var out finding.Set
	for _, c := range textCarriers(src.Bytes) {
		out = append(out, d.report(c, src.Bytes)...)
	}
	return out, nil
}

// carrier is one place a credential was found, before it is read.
type carrier struct {
	// what names the carrier in a finding: "variation selectors", "manifest
	// block", "<script type=\"application/c2pa\">".
	what string
	// at is the whole thing's extent in the file, which is what a removal deletes.
	at Extent
	// hashed is the extent the claim excludes from its hash, which is the same as
	// `at` for every text carrier the specification defines.
	hashed Extent
	// store is the decoded manifest store, nil for a reference or a wrapper that
	// did not decode.
	store []byte
	// url is where the manifest lives, for a reference.
	url string
	// normalisationRisk marks the carrier whose hash is defined over NFC.
	normalisationRisk bool
}

// textCarriers finds every place in a text document that a manifest can ride.
//
// The two cheap tests come first. Every carrier but one spells "c2pa" somewhere
// in the file, and the one that does not is introduced by a zero-width no-break
// space — so a directory scan of a few thousand ordinary text files does two
// substring searches each and stops, rather than lower-casing every one of them.
func textCarriers(data []byte) []carrier {
	marked := bytes.ContainsRune(data, zeroWidthNoBreakSpace)
	named := bytes.Contains(data, []byte("c2pa")) || bytes.Contains(data, []byte("C2PA"))
	if !marked && !named {
		return nil
	}

	var out []carrier
	if marked {
		if c, ok := wrapperCarrier(data); ok {
			out = append(out, c)
		}
	}
	if !named {
		return out
	}
	if c, ok := blockCarrier(data); ok {
		out = append(out, c)
	}
	if c, ok := scriptCarrier(data); ok {
		out = append(out, c)
	}
	if c, ok := linkCarrier(data); ok {
		out = append(out, c)
	}
	return out
}

func (d Text) report(c carrier, file []byte) finding.Set {
	span := finding.Span{Offset: c.at.Offset, Length: c.at.Length, Exact: true}

	if c.store == nil && c.url != "" {
		// A reference: the manifest is somewhere else. augur does not go and get
		// it, and saying so is the finding — a credential whose contents you
		// cannot see is a different situation from one you can.
		label := fmt.Sprintf("C2PA Content Credential stored elsewhere, referenced by this file (%s)", c.what)
		return finding.Set{
			finding.New(d.Name(), KindReference, finding.Provenance, finding.Notice, span, label,
				"The file names a provenance manifest kept at another address. augur reads files "+
					"and fetches nothing, so what that manifest says is not knowable from here — "+
					"only that this file points at it.").
				WithDetail(finding.NewTable("c2pa-reference", []finding.KV{
					{Key: "manifest at", Value: c.url},
					{Key: "carried as", Value: c.what},
				})).Deletable(),
		}
	}

	if c.store == nil {
		return finding.Set{
			finding.New(d.Name(), KindManifest, finding.Provenance, finding.Concern, span,
				fmt.Sprintf("C2PA wrapper in this text that does not decode (%s, %d bytes)", c.what, c.at.Length),
				"Something announced itself as a Content Credential and then did not hold one. "+
					"Whatever these bytes are, they travel with the text and are shown by nothing.").
				Deletable(),
		}
	}

	var report Report
	switch {
	case c.normalisationRisk && !nfcSafe(file, c.hashed):
		// The hash for this carrier is defined over NFC-normalised text, and
		// augur has no normaliser. Where normalising could change a byte, the
		// check does not run rather than run against bytes that may not be the
		// ones the claim was written over.
		report = Read(c.store, nil)
		report.Binding.Note = "not checked: this carrier's hash is defined over NFC-normalised text, " +
			"and this text contains characters normalisation could change"
	default:
		report = Read(c.store, file, c.hashed)
	}

	label := fmt.Sprintf("C2PA Content Credential in this text (%s, %d bytes)", c.what, len(c.store))
	severity := finding.Notice
	if summary := report.Summary(); summary != "" {
		label += " — " + summary
	}
	if report.Err != nil {
		severity = finding.Concern
		label = fmt.Sprintf("C2PA wrapper in this text that does not parse as a manifest (%s, %d bytes)",
			c.what, len(c.store))
	}

	out := finding.Set{
		finding.New(d.Name(), KindManifest, finding.Provenance, severity, span, label,
			"A signed record of where this text came from, carried in the text itself. Nothing "+
				"that renders the document shows it, and it survives copy and paste — which is "+
				"the point of putting it there.").
			WithDetail(finding.NewTable("c2pa", report.Rows())).Deletable(),
	}

	if report.Mismatched() {
		out = append(out, finding.New(d.Name(), KindBroken, finding.Provenance, finding.Concern,
			span, "the Content Credential no longer matches this text",
			"The manifest carries a hash over the text, and the text no longer hashes to it. "+
				"Something was edited after it was signed — which for a document meant to be "+
				"edited is ordinary, and for one presented as unaltered is not.").
			WithDetail(finding.NewTable("c2pa-binding", []finding.KV{
				{Key: "algorithm", Value: report.Binding.Alg},
				{Key: "claim says", Value: report.Binding.Expected},
				{Key: "text hashes to", Value: report.Binding.Actual, Sensitive: true},
			})).
			Irremovable("Nothing can be removed to fix this: the mismatch is a fact about the "+
				"text's history, not a character in it."))
	}
	return out
}

// ---------------------------------------------------------------------------
// the carriers
// ---------------------------------------------------------------------------

// zeroWidthNoBreakSpace introduces a wrapper. The specification requires it in
// front of the selector run, which gives a scan one cheap byte to look for.
const zeroWidthNoBreakSpace = '\uFEFF'

// textWrapperMagic opens a C2PATextManifestWrapper: "C2PATXT\x00".
var textWrapperMagic = []byte("C2PATXT\x00")

// wrapperCarrier finds a manifest encoded as variation selectors.
//
// The encoding is one byte per selector: U+FE00..U+FE0F for the low sixteen
// values and U+E0100..U+E01EF for the rest. A wrapper is introduced by a
// zero-width no-break space and opens with a magic number, which is what makes
// this an identification rather than a guess about a run of invisible characters.
func wrapperCarrier(data []byte) (carrier, bool) {
	text := string(data)
	for i, r := range text {
		if r != zeroWidthNoBreakSpace {
			continue
		}
		decoded, end := decodeSelectorRun(text, i+utf8.RuneLen(r))
		if len(decoded) < 13 || !bytes.HasPrefix(decoded, textWrapperMagic) {
			continue
		}
		at := Extent{Offset: i, Length: end - i}
		length := int(binary.BigEndian.Uint32(decoded[9:13]))

		// A wrapper whose declared length is not there is what the specification
		// calls corrupted. Reported as a wrapper that did not decode, because
		// that is what it is.
		if length <= 0 || 13+length > len(decoded) {
			return carrier{what: "variation selectors", at: at}, true
		}
		return carrier{
			what:              "variation selectors",
			at:                at,
			hashed:            at,
			store:             decoded[13 : 13+length],
			normalisationRisk: true,
		}, true
	}
	return carrier{}, false
}

// decodeSelectorRun reads the contiguous run of variation selectors starting at
// `from`, returning the bytes they encode and where the run ends.
func decodeSelectorRun(text string, from int) ([]byte, int) {
	var out []byte
	at := from
	for _, r := range text[from:] {
		b, ok := selectorByte(r)
		if !ok {
			break
		}
		out = append(out, b)
		at += utf8.RuneLen(r)
	}
	return out, at
}

func selectorByte(r rune) (byte, bool) {
	switch {
	case r >= 0xFE00 && r <= 0xFE0F:
		return byte(r - 0xFE00), true
	case r >= 0xE0100 && r <= 0xE01EF:
		return byte(r-0xE0100) + 16, true
	}
	return 0, false
}

const (
	blockBegin    = "-----BEGIN C2PA MANIFEST-----"
	blockEnd      = "-----END C2PA MANIFEST-----"
	dataURIPrefix = "data:application/c2pa;base64,"
)

// blockCarrier finds the ASCII-armoured manifest block that structured text —
// source, YAML, Markdown front matter — carries in a comment.
func blockCarrier(data []byte) (carrier, bool) {
	start := bytes.Index(data, []byte(blockBegin))
	if start < 0 {
		return carrier{}, false
	}
	endAt := bytes.Index(data[start:], []byte(blockEnd))
	if endAt < 0 {
		return carrier{}, false
	}
	end := start + endAt + len(blockEnd)
	reference := strings.TrimSpace(string(data[start+len(blockBegin) : start+endAt]))
	if !isReference(reference) {
		// Two delimiters with something else between them. Source code that
		// mentions the delimiters — this file, for one — would otherwise be
		// reported as carrying a credential it plainly does not.
		return carrier{}, false
	}

	c := carrier{
		what:   "manifest block",
		at:     Extent{Offset: start, Length: end - start},
		hashed: Extent{Offset: start, Length: end - start},
	}
	c.store, c.url = manifestReference(reference)
	return c, true
}

// isReference reports whether what sits between the delimiters is the one thing
// the specification allows there: a single reference, which is either a URL with
// no spaces in it or a base64 data URI, wrapped across lines or not.
func isReference(ref string) bool {
	if ref == "" {
		return false
	}
	if rest, ok := strings.CutPrefix(ref, dataURIPrefix); ok {
		return isBase64(strings.Join(strings.Fields(rest), ""))
	}
	return len(strings.Fields(ref)) == 1 && !strings.ContainsAny(ref, "<>\"'")
}

func isBase64(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9',
			r == '+', r == '/', r == '=':
		default:
			return false
		}
	}
	return true
}

// scriptCarrier finds an inline manifest in an HTML document.
func scriptCarrier(data []byte) (carrier, bool) {
	lower := bytes.ToLower(data)
	at := bytes.Index(lower, []byte(`application/c2pa"`))
	if at < 0 {
		at = bytes.Index(lower, []byte(`application/c2pa'`))
	}
	if at < 0 {
		return carrier{}, false
	}
	open := bytes.LastIndex(lower[:at], []byte("<script"))
	if open < 0 {
		return carrier{}, false
	}
	bodyAt := bytes.IndexByte(data[at:], '>')
	if bodyAt < 0 {
		return carrier{}, false
	}
	bodyAt += at + 1
	closeAt := bytes.Index(lower[bodyAt:], []byte("</script>"))
	if closeAt < 0 {
		return carrier{}, false
	}
	end := bodyAt + closeAt + len("</script>")

	body := strings.Join(strings.Fields(string(data[bodyAt:bodyAt+closeAt])), "")
	if !isBase64(body) {
		// The element holds something that is not the encoding the specification
		// requires. Source code that quotes the element — this file, for one —
		// matches everything up to here.
		return carrier{}, false
	}
	store, err := decodeBase64(body)
	if err != nil {
		return carrier{}, false
	}
	return carrier{
		what:   `<script type="application/c2pa">`,
		at:     Extent{Offset: open, Length: end - open},
		hashed: Extent{Offset: open, Length: end - open},
		store:  store,
	}, true
}

// linkCarrier finds an HTML link element pointing at a manifest kept elsewhere.
func linkCarrier(data []byte) (carrier, bool) {
	lower := bytes.ToLower(data)
	at := bytes.Index(lower, []byte(`rel="c2pa-manifest"`))
	if at < 0 {
		at = bytes.Index(lower, []byte(`rel='c2pa-manifest'`))
	}
	if at < 0 {
		return carrier{}, false
	}
	open := bytes.LastIndex(lower[:at], []byte("<link"))
	if open < 0 {
		return carrier{}, false
	}
	closeAt := bytes.IndexByte(data[at:], '>')
	if closeAt < 0 {
		return carrier{}, false
	}
	end := at + closeAt + 1

	href := attribute(string(data[open:end]), "href")
	if href == "" {
		// The attribute is what makes this a reference. Without it there is
		// nothing being pointed at, and something else — source code about C2PA,
		// most likely — matched the relation string.
		return carrier{}, false
	}
	return carrier{
		what: `<link rel="c2pa-manifest">`,
		at:   Extent{Offset: open, Length: end - open},
		url:  href,
	}, true
}

// manifestReference reads what a manifest block points at: a data: URI carrying
// the store, or a URL naming where it is kept.
func manifestReference(ref string) (store []byte, url string) {
	if i := strings.Index(ref, dataURIPrefix); i >= 0 {
		if decoded, err := decodeBase64(ref[i+len(dataURIPrefix):]); err == nil {
			return decoded, ""
		}
		return nil, ""
	}
	if fields := strings.Fields(ref); len(fields) > 0 {
		return nil, fields[0]
	}
	return nil, ""
}

// attribute pulls one attribute value out of a tag, in either quoting style.
func attribute(tag, name string) string {
	lower := strings.ToLower(tag)
	at := strings.Index(lower, name+"=")
	if at < 0 {
		return ""
	}
	rest := tag[at+len(name)+1:]
	if rest == "" {
		return ""
	}
	if quote := rest[0]; quote == '"' || quote == '\'' {
		if end := strings.IndexByte(rest[1:], quote); end >= 0 {
			return rest[1 : 1+end]
		}
		return ""
	}
	if fields := strings.Fields(rest); len(fields) > 0 {
		return strings.TrimRight(fields[0], ">")
	}
	return ""
}

// decodeBase64 accepts the encoding with whatever whitespace the host format put
// in it, which for an HTML element or a wrapped comment line is a certainty.
func decodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
}

// nfcSafe reports whether this text is unchanged by Unicode NFC normalisation,
// conservatively.
//
// The hash over unstructured text is defined over the normalised form, and augur
// has no normaliser — bringing one in would mean a dependency and a table, for one
// carrier. So the question asked here is the narrower one that can be answered
// without either: could normalising this text change any byte at all? Where it
// plainly could not, the raw bytes are the normalised bytes and the check is
// exact. Where it could, the check does not run, and says why. Wrong in the safe
// direction: it declines to check text it might have got right, and never claims
// a mismatch it cannot stand behind.
func nfcSafe(data []byte, skip Extent) bool {
	// The question is about the bytes the claim hashed, which excludes the
	// wrapper — and the wrapper is a run of variation selectors, every one of
	// which is a combining mark. Asking about the whole file would answer "not
	// safe" for every wrapper there has ever been, and the check would never run.
	hashed := string(data)
	if skip.Length > 0 && skip.Offset >= 0 && skip.Offset+skip.Length <= len(data) {
		hashed = string(data[:skip.Offset]) + string(data[skip.Offset+skip.Length:])
	}
	for _, r := range hashed {
		switch {
		case r < 0x0300:
			continue // nothing below the combining marks composes
		case unicode.Is(unicode.M, r):
			return false // a combining mark may compose with what precedes it
		case r >= 0x1100 && r <= 0x11FF, // Hangul jamo compose into syllables
			r >= 0xA960 && r <= 0xA97F,
			r >= 0xD7B0 && r <= 0xD7FF:
			return false
		case r >= 0xF900 && r <= 0xFAFF, // CJK compatibility ideographs
			r >= 0x2F800 && r <= 0x2FA1F:
			return false
		case r == 0x2126 || r == 0x212A || r == 0x212B || r == 0x0374 ||
			r == 0x037E || r == 0x0387 || r == 0x1FBE || r == 0x1FEF ||
			r == 0x1FFD || r == 0x309B || r == 0x309C:
			return false // singletons: normalisation replaces these outright
		}
	}
	return true
}
