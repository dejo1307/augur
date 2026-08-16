package text

import (
	"fmt"
	"strings"

	"github.com/dejo1307/augur/pkg/detect"
	"github.com/dejo1307/augur/pkg/finding"
)

const (
	KindHiddenElement   = finding.Kind("hidden-element")
	KindHTMLComment     = finding.Kind("html-comment")
	KindMarkdownComment = finding.Kind("markdown-comment")
)

// Markup finds text that markup hides: an element styled to be unreadable, a
// comment, a markdown construct that renders as nothing.
//
// Every other detector in this package is looking for characters you cannot see.
// This one is looking for ordinary characters — a plain English sentence, in
// ASCII, that a person reading the document will never encounter, because the
// document is rendered before they read it and the rendering leaves it out.
//
// It matters most in exactly the files `augur agents` was written for, and it
// matters there in the reverse of the usual direction. A model reads CLAUDE.md as
// source; a person reviews it as rendered markdown in a browser. A `<span
// style="font-size:0">` is invisible to the reviewer and is instruction to the
// model — the same gap between what is read and what is shown that this whole
// tool exists to close, arriving through the document format rather than through
// the character set.
type Markup struct{}

func (Markup) Name() string { return "markup" }

func (Markup) Applies(f detect.Format) bool { return true }

func (d Markup) Detect(src *detect.Source) (finding.Set, error) {
	var out finding.Set
	for _, region := range src.Regions {
		comments := d.comments(region)
		out = append(out, comments...)
		out = append(out, d.elements(region, spansOf(comments))...)
		out = append(out, d.markdown(region)...)
	}
	return out, nil
}

// span is a byte range within one region, used to keep this detector's own
// findings from crossing each other.
type span struct{ at, end int }

func spansOf(set finding.Set) []span {
	out := make([]span, 0, len(set))
	for _, f := range set {
		out = append(out, span{f.Span.Offset, f.Span.End()})
	}
	return out
}

// straddles reports whether a range crosses the boundary of one of the others
// without either containing it or being contained by it.
//
// Malformed markup can produce exactly that — `<div hidden>a<!-- b </div> -->`
// leaves an element and a comment each half inside the other — and two removable
// findings that each claim bytes the other does not are a pair the cleaner is
// right to refuse. Refusing is the correct behaviour for a contradiction and the
// wrong outcome for the user, so the contradiction is not emitted: nesting is
// fine, crossing is dropped, and the whole selection stays applicable.
func straddles(at, end int, others []span) bool {
	for _, o := range others {
		overlapping := at < o.end && o.at < end
		contained := at >= o.at && end <= o.end
		containing := o.at >= at && o.end <= end
		if overlapping && !contained && !containing {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// comments
// ---------------------------------------------------------------------------

func (d Markup) comments(r detect.Region) finding.Set {
	var out finding.Set
	s := r.Text
	for i := 0; i+4 <= len(s); {
		start := strings.Index(s[i:], "<!--")
		if start < 0 {
			break
		}
		start += i
		end := strings.Index(s[start+4:], "-->")
		if end < 0 {
			break // unterminated: the rest of the file is not a comment, it is a typo
		}
		end = start + 4 + end + 3
		body := strings.TrimSpace(s[start+4 : end-3])

		span := r.Span(start, end-start)
		f := finding.New(d.Name(), KindHTMLComment, finding.Invisible, finding.Notice, span,
			fmt.Sprintf("HTML comment: %q", truncate(body, 60)),
			"Not shown when the document is rendered, and read in full by anything that reads "+
				"the source. Usually a note to a human; in a file that is fed to a model, it is "+
				"text the model sees and the reviewer does not.").
			WithDetail(finding.NewTable("comment", []finding.KV{{Key: "text", Value: truncate(body, 400)}}))
		if span.Exact {
			f = f.Deletable()
		} else {
			f = f.Irremovable("Found inside re-encoded text.")
		}
		out = append(out, f)
		i = end
	}
	return out
}

// markdown finds the comment forms markdown has, which are link references that
// are never referenced and therefore render as nothing at all.
func (d Markup) markdown(r detect.Region) finding.Set {
	var out finding.Set
	s := r.Text
	at := 0
	for _, line := range strings.SplitAfter(s, "\n") {
		trimmed := strings.TrimLeft(line, " \t")
		lead := len(line) - len(trimmed)
		body, ok := markdownComment(strings.TrimRight(trimmed, "\r\n"))
		if !ok {
			at += len(line)
			continue
		}

		span := r.Span(at+lead, len(strings.TrimRight(trimmed, "\r\n")))
		f := finding.New(d.Name(), KindMarkdownComment, finding.Invisible, finding.Notice, span,
			fmt.Sprintf("markdown comment: %q", truncate(body, 60)),
			"A link reference that nothing links to, which is markdown's idiom for a comment: "+
				"it renders as nothing and stays in the source.").
			WithDetail(finding.NewTable("comment", []finding.KV{{Key: "text", Value: truncate(body, 400)}}))
		if span.Exact {
			f = f.Deletable()
		} else {
			f = f.Irremovable("Found inside re-encoded text.")
		}
		out = append(out, f)
		at += len(line)
	}
	return out
}

// markdownComment recognises the two conventional spellings, `[//]: # (text)` and
// `[comment]: <> (text)`.
func markdownComment(line string) (string, bool) {
	if !strings.HasPrefix(line, "[") {
		return "", false
	}
	close := strings.Index(line, "]:")
	if close < 0 {
		return "", false
	}
	label := line[1:close]
	if label != "//" && !strings.EqualFold(label, "comment") {
		return "", false
	}
	rest := strings.TrimSpace(line[close+2:])
	switch {
	case strings.HasPrefix(rest, "#"):
		rest = strings.TrimSpace(rest[1:])
	case strings.HasPrefix(rest, "<>"):
		rest = strings.TrimSpace(rest[2:])
	default:
		return "", false
	}
	return strings.Trim(rest, "()\""), true
}

// ---------------------------------------------------------------------------
// hidden elements
// ---------------------------------------------------------------------------

// concealment is one way of making an element unreadable, and how much it says
// about intent.
type concealment struct {
	pattern string
	says    string
	severe  bool
}

// concealments are matched against an element's start tag with whitespace
// removed, so `font-size: 0` and `font-size:0` are the same thing.
//
// The severe ones are graded that way because they have no other use. Hiding an
// element with `display:none` is how every menu, modal and template on the web
// works, and a document full of them is a document, not an attack. Setting text
// to zero pixels, or to the colour of the paper, or to a position off the side of
// the page, keeps the text in the reading order of everything that is not a pair
// of eyes — which is a thing people do on purpose and rarely by accident.
// nolint:misspell // "color" is the CSS property; the prose around it is British.
var concealments = []concealment{
	{"font-size:0", "text is set to zero size", true},
	{"font-size:0px", "text is set to zero size", true},
	{"opacity:0", "text is fully transparent", true},
	{"color:transparent", "text is fully transparent", true},
	{"color:#fff", "text is the colour of the page", true},
	{"color:#ffffff", "text is the colour of the page", true},
	{"color:white", "text is the colour of the page", true},
	{"color:rgb(255,255,255)", "text is the colour of the page", true},
	{"text-indent:-", "text is indented off the page", true},
	{"left:-9999", "text is positioned off the page", true},
	{"left:-999", "text is positioned off the page", true},
	{"clip:rect(0,0,0,0)", "text is clipped to nothing", true},
	{"clip-path:inset(100%)", "text is clipped to nothing", true},
	{"height:0", "the element has no height", true},
	{"width:0", "the element has no width", true},
	{"display:none", "the element is not displayed", false},
	{"visibility:hidden", "the element is not displayed", false},
}

func (d Markup) elements(r detect.Region, avoid []span) finding.Set {
	var out finding.Set
	s := r.Text
	for i := 0; i < len(s); {
		tag, ok := tagAt(s, i)
		if !ok {
			i++
			continue
		}
		i = tag.end

		how, severe, found := concealedBy(tag.raw)
		if !found {
			continue
		}

		// The element's extent, so the finding covers the hidden text and not
		// just the tag that hid it. Without a close tag there is no telling where
		// the hidden region stops, and a finding that guesses at its own span is
		// one that removes the wrong bytes.
		end, matched := elementEnd(s, tag)
		inner := ""
		if matched {
			inner = strings.TrimSpace(stripTags(s[tag.end : end-len(tag.name)-3]))
		}
		if inner == "" {
			continue // an empty hidden container is layout, not concealment
		}
		if straddles(tag.at, end, avoid) {
			continue
		}

		sev := finding.Concern
		if severe {
			sev = finding.Alarm
		}
		span := r.Span(tag.at, end-tag.at)
		f := finding.New(d.Name(), KindHiddenElement, finding.Invisible, sev, span,
			fmt.Sprintf("hidden <%s>: %s — %q", tag.name, how, truncate(inner, 60)),
			"Text that is in the document and not in the rendered page. Anything reading the "+
				"source — a model, a scraper, a search index — reads it in full, and the person "+
				"looking at the page has no way to know it is there.").
			WithDetail(finding.NewTable("hidden-element", []finding.KV{
				{Key: "how", Value: how},
				{Key: "text", Value: truncate(inner, 400), Sensitive: true},
			}))
		if span.Exact {
			f = f.Deletable()
		} else {
			f = f.Irremovable("Found inside re-encoded text.")
		}
		out = append(out, f)
		i = end
	}
	return out
}

func concealedBy(startTag string) (how string, severe, found bool) {
	flat := strings.ToLower(strings.Join(strings.Fields(startTag), ""))
	for _, c := range concealments {
		if strings.Contains(flat, c.pattern) {
			return c.says, c.severe, true
		}
	}
	// The bare `hidden` attribute, which has to be matched as an attribute rather
	// than as a substring: "hidden" appears inside plenty of class names.
	if hasBareAttr(startTag, "hidden") {
		return "the element carries the hidden attribute", false, true
	}
	if strings.Contains(flat, `aria-hidden="true"`) || strings.Contains(flat, "aria-hidden='true'") {
		return "the element is hidden from assistive technology", false, true
	}
	return "", false, false
}

// hasBareAttr reports whether a start tag carries an attribute with no value.
func hasBareAttr(startTag, name string) bool {
	for _, field := range strings.Fields(strings.Trim(startTag, "<>/")) {
		if strings.EqualFold(field, name) {
			return true
		}
	}
	return false
}

// tag is one start tag, located.
type tag struct {
	at         int    // offset of '<'
	end        int    // offset just past '>'
	name       string // lower-cased element name
	raw        string // the tag as written
	selfClosed bool
}

// tagAt parses a start tag beginning at i, if one begins there.
func tagAt(s string, i int) (tag, bool) {
	if i >= len(s) || s[i] != '<' {
		return tag{}, false
	}
	j := i + 1
	if j < len(s) && (s[j] == '/' || s[j] == '!' || s[j] == '?') {
		return tag{}, false
	}
	start := j
	for j < len(s) && isNameByte(s[j]) {
		j++
	}
	if j == start {
		return tag{}, false
	}
	name := strings.ToLower(s[start:j])

	// Attributes, respecting quotes so a '>' inside an attribute value does not
	// end the tag early.
	var quote byte
	for ; j < len(s); j++ {
		c := s[j]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '>':
			raw := s[i : j+1]
			return tag{at: i, end: j + 1, name: name, raw: raw,
				selfClosed: strings.HasSuffix(strings.TrimSpace(raw[:len(raw)-1]), "/")}, true
		case c == '<':
			return tag{}, false // an unterminated tag is not a tag
		}
	}
	return tag{}, false
}

func isNameByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_'
}

// elementEnd returns the offset just past the element's closing tag, and whether
// one was found. Nesting of the same element name is counted, so the close tag
// matched is the one that belongs to this open tag.
func elementEnd(s string, t tag) (int, bool) {
	if t.selfClosed {
		return t.end, false
	}
	depth := 1
	open, close := "<"+t.name, "</"+t.name
	for i := t.end; i < len(s); {
		switch {
		case strings.HasPrefix(strings.ToLower(s[i:min(i+len(close)+1, len(s))]), close):
			depth--
			j := strings.IndexByte(s[i:], '>')
			if j < 0 {
				return t.end, false
			}
			if depth == 0 {
				return i + j + 1, true
			}
			i += j + 1
		case strings.HasPrefix(strings.ToLower(s[i:min(i+len(open)+1, len(s))]), open):
			if nested, ok := tagAt(s, i); ok && nested.name == t.name {
				if !nested.selfClosed {
					depth++
				}
				i = nested.end
				continue
			}
			i++
		default:
			i++
		}
	}
	return t.end, false
}

// stripTags reduces an element's contents to the text a reader would see if it
// were not hidden, which is what the finding needs to quote.
func stripTags(s string) string {
	var b strings.Builder
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '<':
			depth++
		case '>':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 {
				b.WriteByte(s[i])
			}
		}
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

// truncate shortens a quoted string for a one-line label.
func truncate(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
