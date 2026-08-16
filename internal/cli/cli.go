// Package cli is the headless surface: the verbs a pipeline or a script uses.
//
// It exists as much for the architecture as for the user. An engine with one
// caller is never proved separable, and the viewer would slowly have absorbed
// logic that belongs underneath it. Two callers over one session package keeps
// that honest.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/dejo1307/augur/internal/agents"
	"github.com/dejo1307/augur/internal/report"
	"github.com/dejo1307/augur/internal/session"
	"github.com/dejo1307/augur/internal/upgrade"
	"github.com/dejo1307/augur/pkg/finding"
)

// Exit codes, which are part of the interface: a CI job branches on these.
const (
	ExitClean    = 0 // nothing hidden found
	ExitFindings = 1 // findings present
	ExitError    = 2 // could not read or parse the file
)

// Scan implements `augur scan FILE [--json] [--min-severity=...]`.
func Scan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "write findings as JSON")
	minSev := fs.String("min-severity", "notice", "notice, concern or alarm")
	if err := fs.Parse(args); err != nil {
		return ExitError
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: augur scan FILE [--json] [--min-severity=notice|concern|alarm]")
		return ExitError
	}

	threshold, err := parseSeverity(*minSev)
	if err != nil {
		fmt.Fprintln(stderr, "augur:", err)
		return ExitError
	}

	s, err := session.Open(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(stderr, "augur:", err)
		return ExitError
	}

	// A detector that failed is reported and changes the exit code. Reporting a
	// file as clean when part of the scan did not run would be the worst possible
	// silent failure.
	for _, e := range s.Result.Errors {
		fmt.Fprintln(stderr, "augur:", e)
	}
	if len(s.Result.Errors) > 0 {
		return ExitError
	}

	set := atLeast(s.Findings(), threshold)
	if *asJSON {
		if err := report.JSON(stdout, s.Path, string(s.Result.Source.Format), set); err != nil {
			fmt.Fprintln(stderr, "augur:", err)
			return ExitError
		}
	} else if err := report.Text(stdout, s.Path, string(s.Result.Source.Format), set); err != nil {
		fmt.Fprintln(stderr, "augur:", err)
		return ExitError
	}

	if len(set) > 0 {
		return ExitFindings
	}
	return ExitClean
}

// Clean implements `augur clean FILE [-o OUT] [--categories=...] [--force]`.
func Clean(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("clean", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("o", "", "destination (default: alongside the original, with .clean before the extension)")
	cats := fs.String("categories", "", "only remove these categories, comma-separated (default: everything removable)")
	force := fs.Bool("force", false, "overwrite the destination if it exists")
	if err := fs.Parse(args); err != nil {
		return ExitError
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: augur clean FILE [-o OUT] [--categories=invisible,metadata] [--force]")
		return ExitError
	}

	s, err := session.Open(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(stderr, "augur:", err)
		return ExitError
	}
	for _, e := range s.Result.Errors {
		fmt.Fprintln(stderr, "augur:", e)
	}
	if len(s.Result.Errors) > 0 {
		return ExitError
	}

	if *cats != "" {
		want, err := parseCategories(*cats)
		if err != nil {
			fmt.Fprintln(stderr, "augur:", err)
			return ExitError
		}
		s.SelectNone()
		for _, f := range s.Removable() {
			if want[f.Category] {
				s.Toggle(f.ID)
			}
		}
	}

	dest := *out
	if dest == "" {
		dest = session.DefaultDest(s.Path)
	}

	v, err := s.Save(dest, *force)
	if err != nil {
		if errors.Is(err, session.ErrWouldOverwrite) {
			fmt.Fprintf(stderr, "augur: %v (pass --force to replace it)\n", err)
		} else {
			fmt.Fprintln(stderr, "augur:", err)
		}
		return ExitError
	}

	fmt.Fprintf(stdout, "wrote %s\n%s\n", v.Path, v)
	if !v.OK() {
		return ExitError
	}
	if len(v.Remaining) > 0 {
		return ExitFindings
	}
	return ExitClean
}

// Agents implements `augur agents [--list] [--json] [--project DIR]`.
//
// It finds the instruction files the coding agents on this machine read, and
// scans them with the same detectors everything else uses. Nothing about the
// scanning is special here — what is special is the target: files a model reads
// on every session and a human reads approximately never.
func Agents(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("agents", flag.ContinueOnError)
	fs.SetOutput(stderr)
	list := fs.Bool("list", false, "list the instruction files found and exit, without scanning")
	asJSON := fs.Bool("json", false, "write the result as JSON")
	project := fs.String("project", ".", "project root to search for repository-local instructions")
	// Defaults to `concern`, not `notice`. The question this command answers is
	// "is there a hidden instruction in what my agents read", and a stray
	// trailing space is not that — on a real machine it fired for 48 files and
	// buried the answer. The floor is reported in the output, and
	// --min-severity=notice restores everything.
	minSev := fs.String("min-severity", "concern", "notice, concern or alarm")
	if err := fs.Parse(args); err != nil {
		return ExitError
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: augur agents [--list] [--json] [--project DIR]")
		return ExitError
	}

	threshold, err := parseSeverity(*minSev)
	if err != nil {
		fmt.Fprintln(stderr, "augur:", err)
		return ExitError
	}

	roots, err := agents.DefaultRoots(*project)
	if err != nil {
		fmt.Fprintln(stderr, "augur:", err)
		return ExitError
	}
	found := agents.Discover(roots)

	if *list {
		if *asJSON {
			return jsonOr(stderr, stdout, report.AgentsListJSON(stdout, roots, found))
		}
		report.AgentsList(stdout, roots, found)
		return ExitClean
	}

	// Scan every discovered file. A file that cannot be read is reported rather
	// than skipped: "we did not look at this one" must never render as "clean".
	scanned := make([]report.AgentFile, 0, agents.Count(found))
	for _, inst := range found {
		for _, f := range inst.Files {
			entry := report.AgentFile{Found: f}
			if s, err := session.Open(f.Path); err != nil {
				entry.Err = err
			} else {
				all := s.Findings()
				entry.Findings = atLeast(all, threshold)
				entry.Suppressed = len(all) - len(entry.Findings)
			}
			scanned = append(scanned, entry)
		}
	}

	if *asJSON {
		return jsonOr(stderr, stdout, report.AgentsJSON(stdout, roots, found, scanned))
	}
	if err := report.Agents(stdout, roots, found, scanned); err != nil {
		fmt.Fprintln(stderr, "augur:", err)
		return ExitError
	}

	// Exit 1 when anything was found, matching `scan`. A CI job can run this to
	// fail a pull request that adds a hidden instruction to an agent file.
	for _, e := range scanned {
		if e.Err != nil {
			return ExitError
		}
		if len(e.Findings) > 0 {
			return ExitFindings
		}
	}
	return ExitClean
}

func jsonOr(stderr, _ io.Writer, err error) int {
	if err != nil {
		fmt.Fprintln(stderr, "augur:", err)
		return ExitError
	}
	return ExitClean
}

// Upgrade implements `augur upgrade [--check] [--force]`.
func Upgrade(args []string, current string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("upgrade", flag.ContinueOnError)
	fs.SetOutput(stderr)
	check := fs.Bool("check", false, "report whether a newer release exists and exit, changing nothing")
	force := fs.Bool("force", false, "re-install even when already on the latest release")
	if err := fs.Parse(args); err != nil {
		return ExitError
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: augur upgrade [--check] [--force]")
		return ExitError
	}

	ctx := context.Background()

	if *check {
		res, err := upgrade.Check(ctx, current)
		if err != nil {
			fmt.Fprintln(stderr, "augur:", err)
			return ExitError
		}
		switch {
		case res.Dev:
			fmt.Fprintf(stdout, "this build is %q; the latest release is v%s\n", res.Current, res.Latest)
		case res.Newer:
			fmt.Fprintf(stdout, "augur v%s is available (running v%s)\n", res.Latest, res.Current)
		default:
			fmt.Fprintf(stdout, "augur v%s is the latest release\n", res.Current)
		}
		// Exit 1 when something is available, so a script can branch on it —
		// the same shape as `scan` reporting findings.
		if res.Newer {
			return ExitFindings
		}
		return ExitClean
	}

	if err := upgrade.Run(ctx, current, stdout, *force); err != nil {
		fmt.Fprintln(stderr, "augur:", err)
		return ExitError
	}
	return ExitClean
}

func parseSeverity(s string) (finding.Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "notice":
		return finding.Notice, nil
	case "concern":
		return finding.Concern, nil
	case "alarm":
		return finding.Alarm, nil
	}
	return finding.Notice, fmt.Errorf("unknown severity %q (want notice, concern or alarm)", s)
}

func parseCategories(s string) (map[finding.Category]bool, error) {
	known := map[finding.Category]bool{}
	for _, c := range finding.Categories() {
		known[c] = true
	}
	out := map[finding.Category]bool{}
	for _, part := range strings.Split(s, ",") {
		c := finding.Category(strings.ToLower(strings.TrimSpace(part)))
		if !known[c] {
			return nil, fmt.Errorf("unknown category %q", part)
		}
		out[c] = true
	}
	return out, nil
}

func atLeast(set finding.Set, min finding.Severity) finding.Set {
	if min == finding.Notice {
		return set
	}
	var out finding.Set
	for _, f := range set {
		if f.Severity >= min {
			out = append(out, f)
		}
	}
	return out
}
