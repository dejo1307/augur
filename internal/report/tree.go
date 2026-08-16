package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/dejo1307/augur/pkg/finding"
)

// TreeFile is one file, scanned, as part of a directory-wide report.
type TreeFile struct {
	Path   string
	Format string
	// Examined is false when no handler reads this file's format, so nothing
	// looked inside it. Carried per file rather than inferred from an empty
	// finding set, because "clean" and "unread" must never render the same.
	Examined bool
	Findings finding.Set
	// Suppressed counts findings below the requested severity.
	Suppressed int
	Err        error
}

// TreeSkip is a path the walk found and did not open, with the reason.
type TreeSkip struct {
	Path   string
	Reason string
}

// TreeResult is everything a directory scan produced.
type TreeResult struct {
	// Root is the path as the user typed it.
	Root string
	// Source is how the file list was produced: "git" or "filesystem". Reported
	// because it decides what the list means — git's answer honours every
	// .gitignore in the tree, the filesystem's honours a list of directory names.
	Source    string
	Threshold finding.Severity
	// MaxSize is the per-file ceiling the walk applied, for the skip line.
	MaxSize int64
	Files   []TreeFile
	Skipped []TreeSkip
	// MaxFiles caps how many flagged files the text report details. Zero is all.
	MaxFiles int
}

type treeCounts struct {
	scanned, examined, flagged, failed int
	quiet, suppressed, findings        int
	bySeverity                         map[finding.Severity]int
}

func (r TreeResult) counts() treeCounts {
	c := treeCounts{bySeverity: map[finding.Severity]int{}}
	for _, f := range r.Files {
		c.scanned++
		if f.Examined {
			c.examined++
		}
		if f.Err != nil {
			c.failed++
		}
		if len(f.Findings) > 0 {
			c.flagged++
		} else if f.Suppressed > 0 {
			c.quiet++
		}
		c.suppressed += f.Suppressed
		c.findings += len(f.Findings)
		for _, x := range f.Findings {
			c.bySeverity[x.Severity]++
		}
	}
	return c
}

// flagged returns the files worth printing: those with findings or an error,
// most severe first, then by path. A repository scan that listed every clean
// file would bury its own answer.
func (r TreeResult) flagged() []TreeFile {
	var out []TreeFile
	for _, f := range r.Files {
		if f.Err != nil || len(f.Findings) > 0 {
			out = append(out, f)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		wi, _ := out[i].Findings.Worst()
		wj, _ := out[j].Findings.Worst()
		if wi != wj {
			return wi > wj
		}
		return out[i].Path < out[j].Path
	})
	return out
}

// Tree writes the human-readable report for a directory scan.
func Tree(w io.Writer, r TreeResult) error {
	e := &errWriter{w: w}
	c := r.counts()

	e.printf("Scanned %d file(s) under %s — %s\n", c.scanned, r.Root, sourceLine(r.Source))
	e.printf("%s\n", coverageLine(r, c))
	if line := thresholdLine(r, c); line != "" {
		e.printf("%s\n", line)
	}

	hits := r.flagged()
	shown := hits
	if r.MaxFiles > 0 && len(shown) > r.MaxFiles {
		shown = shown[:r.MaxFiles]
	}
	for _, f := range shown {
		if f.Err != nil && len(f.Findings) == 0 {
			e.printf("\n? %s\n      could not be read: %v\n", f.Path, f.Err)
			continue
		}
		worst, _ := f.Findings.Worst()
		e.printf("\n%s %s — %d finding(s)\n", mark(worst), f.Path, len(f.Findings))
		if f.Err != nil {
			// A detector failed on a file that also produced findings. Say so:
			// the findings that did come back are not the whole answer.
			e.printf("      incomplete: %v\n", f.Err)
		}
		for _, x := range topFindings(f.Findings, 3) {
			e.printf("      [%s] %s\n", x.Severity, x.Label)
			if d := detailLine(x); d != "" {
				e.printf("        %s\n", d)
			}
		}
		if n := len(f.Findings) - 3; n > 0 {
			e.printf("      … and %d more\n", n)
		}
	}
	if n := len(hits) - len(shown); n > 0 {
		e.printf("\n… and %d more file(s) with findings — --max-files=0 for all, or --json\n", n)
	}

	e.printf("\n")
	if c.flagged == 0 {
		e.printf("Nothing hidden found in any file that was examined.\n")
	} else {
		e.printf("%d file(s) carry something hidden: %s.\n", c.flagged, severityBreakdown(c))
	}
	if c.failed > 0 {
		e.printf("%d file(s) could not be fully read — the scan is incomplete.\n", c.failed)
	}
	return e.err
}

func sourceLine(source string) string {
	if source == "git" {
		return "file list from git: tracked and untracked, .gitignore applied."
	}
	return "file list from the filesystem: build, cache and dependency directories skipped."
}

// coverageLine is the sentence that keeps a directory scan honest. Everything in
// it is a count of files nobody looked inside, which is the one thing a clean
// report at this scale can quietly be hiding.
func coverageLine(r TreeResult, c treeCounts) string {
	parts := []string{fmt.Sprintf("%d examined", c.examined)}
	if n := c.scanned - c.examined; n > 0 {
		parts = append(parts, fmt.Sprintf("%d not examined (no handler reads their format)", n))
	}
	if len(r.Skipped) > 0 {
		parts = append(parts, fmt.Sprintf("%d not opened (%s)", len(r.Skipped), skipBreakdown(r)))
	}
	return strings.Join(parts, "; ") + "."
}

// skipBreakdown groups skipped paths by reason. The paths themselves are in the
// JSON; a terminal wants the shape.
func skipBreakdown(r TreeResult) string {
	byReason := map[string]int{}
	var order []string
	for _, s := range r.Skipped {
		if byReason[s.Reason] == 0 {
			order = append(order, s.Reason)
		}
		byReason[s.Reason]++
	}
	sort.Strings(order)
	parts := make([]string, 0, len(order))
	for _, reason := range order {
		text := reason
		if strings.Contains(reason, "size limit") && r.MaxSize > 0 {
			text = fmt.Sprintf("%s of %d bytes", reason, r.MaxSize)
		}
		parts = append(parts, fmt.Sprintf("%d %s", byReason[reason], text))
	}
	return strings.Join(parts, ", ")
}

func thresholdLine(r TreeResult, c treeCounts) string {
	if r.Threshold == finding.Notice {
		return ""
	}
	line := fmt.Sprintf("Reporting %s and above.", r.Threshold)
	if c.suppressed > 0 {
		line += fmt.Sprintf(" %d lower-severity finding(s) in %d otherwise-clean file(s) not shown; re-run with --min-severity=notice.",
			c.suppressed, c.quiet)
	}
	return line
}

func severityBreakdown(c treeCounts) string {
	var parts []string
	for _, s := range []finding.Severity{finding.Alarm, finding.Concern, finding.Notice} {
		if n := c.bySeverity[s]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, s))
		}
	}
	if len(parts) == 0 {
		return "no findings"
	}
	return strings.Join(parts, ", ")
}

// TreeJSON is the machine-readable form.
//
// It carries every file with findings, every file that failed, and every file
// nothing looked inside — but not the clean, examined majority, which would be
// thousands of entries saying the same thing. The summary counts them, so a
// consumer can still check that the numbers add up.
func TreeJSON(w io.Writer, r TreeResult) error {
	type file struct {
		Path     string      `json:"path"`
		Format   string      `json:"format"`
		Examined bool        `json:"examined"`
		Error    string      `json:"error,omitempty"`
		Count    int         `json:"count"`
		Findings finding.Set `json:"findings,omitempty"`
	}
	type skip struct {
		Path   string `json:"path"`
		Reason string `json:"reason"`
	}

	c := r.counts()
	files := make([]file, 0, len(r.Files))
	for _, f := range r.Files {
		if f.Err == nil && len(f.Findings) == 0 && f.Examined {
			continue
		}
		entry := file{
			Path: f.Path, Format: f.Format, Examined: f.Examined,
			Count: len(f.Findings), Findings: f.Findings,
		}
		if f.Err != nil {
			entry.Error = f.Err.Error()
		}
		files = append(files, entry)
	}
	skips := make([]skip, 0, len(r.Skipped))
	for _, s := range r.Skipped {
		skips = append(skips, skip(s))
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(map[string]any{
		"root":         r.Root,
		"source":       r.Source,
		"min_severity": r.Threshold.String(),
		"summary": map[string]any{
			"scanned":             c.scanned,
			"examined":            c.examined,
			"not_examined":        c.scanned - c.examined,
			"not_opened":          len(r.Skipped),
			"files_with_findings": c.flagged,
			"files_failed":        c.failed,
			"findings":            c.findings,
			"suppressed":          c.suppressed,
		},
		"files":   files,
		"skipped": skips,
	})
}
