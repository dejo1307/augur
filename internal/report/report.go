// Package report renders findings for something other than a screen: a terminal
// that is not a TTY, a pipeline, a log. It reads findings and writes bytes, and
// holds no state.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/dejo1307/augur/internal/runeinfo"
	"github.com/dejo1307/augur/pkg/finding"
)

// JSON writes the whole finding set as one object. Stable field names, because
// this is an interface other programs depend on.
func JSON(w io.Writer, path string, format string, set finding.Set) error {
	type doc struct {
		Path     string      `json:"path"`
		Format   string      `json:"format"`
		Count    int         `json:"count"`
		Findings finding.Set `json:"findings"`
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc{Path: path, Format: format, Count: len(set), Findings: set})
}

// errWriter latches the first write error so a long report can be written as
// straight-line code and still report a broken pipe. Checking every Fprintf by
// hand would bury the shape of the report in error handling for a failure mode
// that is always the same one.
type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) printf(format string, args ...any) {
	if e.err != nil {
		return
	}
	_, e.err = fmt.Fprintf(e.w, format, args...)
}

// Text writes a human-readable report for a terminal without a viewer.
func Text(w io.Writer, path string, format string, set finding.Set) error {
	e := &errWriter{w: w}
	if len(set) == 0 {
		e.printf("%s (%s): nothing hidden found\n", path, format)
		return e.err
	}
	e.printf("%s (%s): %d finding(s)\n", path, format, len(set))

	byCat := set.ByCategory()
	for _, cat := range finding.Categories() {
		group := byCat[cat]
		if len(group) == 0 {
			continue
		}
		e.printf("\n%s\n", strings.ToUpper(string(cat)))
		for _, f := range group {
			mark := " "
			if !f.Removable {
				mark = "*"
			}
			e.printf(" %s [%s] offset %d — %s\n", mark, f.Severity, f.Span.Offset, f.Label)
			if d := detailLine(f); d != "" {
				e.printf("       %s\n", d)
			}
		}
	}
	if len(set.Removable()) < len(set) {
		e.printf("\n* not removable — reported and left in place\n")
	}
	return e.err
}

// detailLine renders a finding's evidence as one line. The decoded message gets
// pride of place: it is the only thing in a report that a reader will act on
// immediately.
func detailLine(f finding.Finding) string {
	switch d := f.Detail.(type) {
	case finding.Decoded:
		if d.Printable {
			return fmt.Sprintf("decodes to (%s): %q", d.Scheme, truncate(d.Text, 120))
		}
		return fmt.Sprintf("decodes to %d bytes of binary (%s)", len(d.Bytes), d.Scheme)
	case finding.Runes:
		if d.Context == "" {
			return ""
		}
		return "in context: " + truncate(Visible(d.Context), 100)
	case finding.Table:
		parts := make([]string, 0, len(d.Rows))
		for _, r := range d.Rows {
			parts = append(parts, r.Key+"="+r.Value)
		}
		return truncate(strings.Join(parts, ", "), 120)
	case finding.Blob:
		if d.Sniffed != "" {
			return fmt.Sprintf("%d bytes, looks like %s", d.Size, d.Sniffed)
		}
		return fmt.Sprintf("%d bytes", d.Size)
	}
	return ""
}

// Visible rewrites text so that invisible characters can be seen, which is the
// one thing a tool for finding invisible characters must never fail to do.
func Visible(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == '\n' {
			b.WriteString("⏎")
			continue
		}
		if r == '\t' {
			b.WriteString("⇥")
			continue
		}
		b.WriteString(runeinfo.Display(r))
	}
	return b.String()
}

func truncate(s string, n int) string {
	if len([]rune(s)) <= n {
		return s
	}
	return string([]rune(s)[:n]) + "…"
}
