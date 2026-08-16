package report_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/dejo1307/augur/internal/report"
	"github.com/dejo1307/augur/pkg/finding"
)

func hidden(sev finding.Severity, label string) finding.Finding {
	return finding.New("text.hidden", "zero-width", finding.Invisible, sev,
		finding.Span{Offset: 3, Length: 3, Exact: true}, label, "why")
}

func sample() report.TreeResult {
	return report.TreeResult{
		Root:      ".",
		Source:    "git",
		Threshold: finding.Concern,
		MaxSize:   1024,
		Files: []report.TreeFile{
			{Path: "a.md", Format: "text", Examined: true, Findings: finding.Set{hidden(finding.Alarm, "smuggled instruction")}},
			{Path: "b.md", Format: "text", Examined: true, Suppressed: 4},
			{Path: "logo.gif", Format: "unknown", Examined: false},
			{Path: "c.bin", Format: "binary", Examined: false, Err: errors.New("permission denied")},
		},
		Skipped: []report.TreeSkip{{Path: "huge.log", Reason: "larger than the size limit"}},
	}
}

func TestTreeReportsCoverageNotJustFindings(t *testing.T) {
	var buf bytes.Buffer
	if err := report.Tree(&buf, sample()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	for _, want := range []string{
		"Scanned 4 file(s)",
		"2 examined",
		"2 not examined", // the two nothing looked inside
		"1 not opened",   // the one the walk passed over
		"larger than the size limit of 1024 bytes",
		"Reporting concern and above",
		"4 lower-severity finding(s)",
		"could not be fully read",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report is missing %q:\n%s", want, out)
		}
	}
}

func TestTreeDetailsOnlyFlaggedFiles(t *testing.T) {
	var buf bytes.Buffer
	if err := report.Tree(&buf, sample()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "a.md — 1 finding(s)") {
		t.Errorf("expected the flagged file to be detailed:\n%s", out)
	}
	// A clean file gets a line in the counts and nowhere else, or a repository
	// scan buries its own answer under thousands of "nothing found".
	if strings.Contains(out, "b.md") {
		t.Errorf("a clean file should not be listed individually:\n%s", out)
	}
}

func TestTreeCapsTheListedFiles(t *testing.T) {
	r := sample()
	r.Files = nil
	for _, name := range []string{"a", "b", "c", "d", "e"} {
		r.Files = append(r.Files, report.TreeFile{
			Path: name + ".md", Format: "text", Examined: true,
			Findings: finding.Set{hidden(finding.Concern, "zero width space")},
		})
	}
	r.MaxFiles = 2

	var buf bytes.Buffer
	if err := report.Tree(&buf, r); err != nil {
		t.Fatal(err)
	}
	if out := buf.String(); !strings.Contains(out, "and 3 more file(s) with findings") {
		t.Errorf("expected the truncation to be stated:\n%s", out)
	}
}

func TestTreeJSONCarriesTheBlindSpots(t *testing.T) {
	var buf bytes.Buffer
	if err := report.TreeJSON(&buf, sample()); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Source  string `json:"source"`
		Summary struct {
			Scanned     int `json:"scanned"`
			Examined    int `json:"examined"`
			NotExamined int `json:"not_examined"`
			NotOpened   int `json:"not_opened"`
			Suppressed  int `json:"suppressed"`
		} `json:"summary"`
		Files []struct {
			Path     string `json:"path"`
			Examined bool   `json:"examined"`
			Error    string `json:"error"`
		} `json:"files"`
		Skipped []struct {
			Path   string `json:"path"`
			Reason string `json:"reason"`
		} `json:"skipped"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}

	if doc.Source != "git" || doc.Summary.Scanned != 4 || doc.Summary.NotExamined != 2 {
		t.Errorf("summary is wrong: %+v", doc.Summary)
	}
	if doc.Summary.Suppressed != 4 {
		t.Errorf("suppressed = %d, want 4", doc.Summary.Suppressed)
	}
	// Clean examined files are counted, not listed. Everything else — findings,
	// failures, and files nothing read — is named, because those are the entries a
	// consumer has to be able to act on.
	listed := map[string]bool{}
	for _, f := range doc.Files {
		listed[f.Path] = true
	}
	if listed["b.md"] {
		t.Error("a clean examined file should not be in the files array")
	}
	for _, want := range []string{"a.md", "logo.gif", "c.bin"} {
		if !listed[want] {
			t.Errorf("%s is missing from the files array", want)
		}
	}
	if len(doc.Skipped) != 1 || doc.Skipped[0].Path != "huge.log" {
		t.Errorf("skipped = %+v", doc.Skipped)
	}
}
