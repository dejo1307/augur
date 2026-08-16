package report

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dejo1307/augur/internal/agents"
	"github.com/dejo1307/augur/pkg/finding"
)

// AgentFile is one discovered instruction file after scanning.
type AgentFile struct {
	Found agents.Found
	// Findings are those at or above the requested severity.
	Findings finding.Set
	// Suppressed counts the findings below it. Reported rather than dropped:
	// a filtered report that does not say it filtered is a lie by omission.
	Suppressed int
	Err        error
}

// AgentsList renders discovery without scanning.
func AgentsList(w io.Writer, roots agents.Roots, installs []agents.Install) {
	e := &errWriter{w: w}
	e.printf("%d agent(s) found, %d instruction file(s)\n", len(installs), agents.Count(installs))
	for _, inst := range installs {
		e.printf("\n%s%s\n", inst.Agent.Name, installedSuffix(inst))
		for _, f := range inst.Files {
			e.printf("  %-6s %s\n", f.Scope, short(roots, f.Path))
		}
	}
}

// Agents renders the scanned result.
//
// Only files with findings are listed individually. A machine with a thousand
// plugin skills would otherwise produce a thousand lines saying "clean", and the
// two that matter would be lost in it — the same reason the catalogue targets
// instruction paths instead of every markdown file it can reach.
func Agents(w io.Writer, roots agents.Roots, installs []agents.Install, scanned []AgentFile) error {
	e := &errWriter{w: w}

	byAgent := map[string][]AgentFile{}
	for _, f := range scanned {
		byAgent[f.Found.Agent.ID] = append(byAgent[f.Found.Agent.ID], f)
	}

	total, flagged, failed, quiet, suppressed := 0, 0, 0, 0, 0
	for _, f := range scanned {
		total++
		switch {
		case f.Err != nil:
			failed++
		case len(f.Findings) > 0:
			flagged++
		case f.Suppressed > 0:
			quiet++
		}
		suppressed += f.Suppressed
	}

	e.printf("Checked %d instruction file(s) across %d agent(s).\n", total, len(installs))

	for _, inst := range installs {
		files := byAgent[inst.Agent.ID]
		hits := make([]AgentFile, 0, len(files))
		for _, f := range files {
			if f.Err != nil || len(f.Findings) > 0 {
				hits = append(hits, f)
			}
		}

		status := fmt.Sprintf("%d file(s)", len(files))
		if len(hits) > 0 {
			status = fmt.Sprintf("%d file(s), %d with findings", len(files), len(hits))
		}
		e.printf("\n%s%s — %s\n", inst.Agent.Name, installedSuffix(inst), status)

		sort.Slice(hits, func(i, j int) bool { return hits[i].Found.Path < hits[j].Found.Path })
		for _, f := range hits {
			if f.Err != nil {
				e.printf("  ? %s\n      could not be read: %v\n", short(roots, f.Found.Path), f.Err)
				continue
			}
			worst, _ := f.Findings.Worst()
			e.printf("  %s %s\n", mark(worst), short(roots, f.Found.Path))
			e.printf("      %s\n", f.Found.Why)
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
	}

	e.printf("\n")
	switch {
	case flagged > 0:
		e.printf("%d file(s) carry something hidden.\n", flagged)
		e.printf("These are read by a model on every session and by a person almost never,\n")
		e.printf("so anything hidden in one is a standing instruction nobody sees.\n")
	default:
		e.printf("Nothing hidden found in any of them.\n")
	}
	if failed > 0 {
		e.printf("%d file(s) could not be read.\n", failed)
	}
	// Name what was filtered out. The floor exists because a single trailing
	// space in each of forty memory files buries the one finding that matters —
	// but a reader who is not told the floor is there cannot judge the result.
	if suppressed > 0 {
		e.printf("%d lower-severity finding(s) in %d file(s) not shown; re-run with --min-severity=notice.\n",
			suppressed, quiet)
	}
	return e.err
}

// AgentsListJSON and AgentsJSON are the machine-readable forms.
func AgentsListJSON(w io.Writer, roots agents.Roots, installs []agents.Install) error {
	type file struct {
		Scope string `json:"scope"`
		Path  string `json:"path"`
		Why   string `json:"why"`
	}
	type entry struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		Installed bool   `json:"installed"`
		Files     []file `json:"files"`
	}
	out := make([]entry, 0, len(installs))
	for _, inst := range installs {
		e := entry{ID: inst.Agent.ID, Name: inst.Agent.Name, Installed: inst.Installed}
		for _, f := range inst.Files {
			e.Files = append(e.Files, file{string(f.Scope), f.Path, f.Why})
		}
		out = append(out, e)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(map[string]any{
		"home": roots.Home, "project": roots.Project, "agents": out,
	})
}

func AgentsJSON(w io.Writer, roots agents.Roots, installs []agents.Install, scanned []AgentFile) error {
	type file struct {
		Agent    string      `json:"agent"`
		Scope    string      `json:"scope"`
		Path     string      `json:"path"`
		Why      string      `json:"why"`
		Error    string      `json:"error,omitempty"`
		Count    int         `json:"count"`
		Findings finding.Set `json:"findings,omitempty"`
	}
	out := make([]file, 0, len(scanned))
	for _, f := range scanned {
		e := file{
			Agent: f.Found.Agent.ID, Scope: string(f.Found.Scope),
			Path: f.Found.Path, Why: f.Found.Why,
			Count: len(f.Findings), Findings: f.Findings,
		}
		if f.Err != nil {
			e.Error = f.Err.Error()
		}
		out = append(out, e)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(map[string]any{
		"home": roots.Home, "project": roots.Project,
		"agents": len(installs), "files": out,
	})
}

// ---------------------------------------------------------------------------

func installedSuffix(inst agents.Install) string {
	if inst.Installed {
		return ""
	}
	// Files without an installed tool still matter: they arrive with a clone and
	// will be read by whoever does have the tool.
	return styleNote(" (not installed here — files present anyway)")
}

func styleNote(s string) string { return s }

// topFindings returns the n most severe findings, most severe first.
func topFindings(s finding.Set, n int) finding.Set {
	sorted := make(finding.Set, len(s))
	copy(sorted, s)
	sorted.Sort()
	if len(sorted) > n {
		sorted = sorted[:n]
	}
	return sorted
}

func mark(s finding.Severity) string {
	switch s {
	case finding.Alarm:
		return "!"
	case finding.Concern:
		return "•"
	default:
		return "·"
	}
}

// short renders a path relative to the home or project root, so a report is
// readable and does not spray absolute paths across a terminal.
func short(roots agents.Roots, p string) string {
	if roots.Project != "" && strings.HasPrefix(p, roots.Project+string(filepath.Separator)) {
		return "./" + strings.TrimPrefix(p, roots.Project+string(filepath.Separator))
	}
	if roots.Home != "" && strings.HasPrefix(p, roots.Home+string(filepath.Separator)) {
		return "~/" + strings.TrimPrefix(p, roots.Home+string(filepath.Separator))
	}
	return p
}
