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
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/dejo1307/augur/internal/agents"
	"github.com/dejo1307/augur/internal/report"
	"github.com/dejo1307/augur/internal/session"
	"github.com/dejo1307/augur/internal/upgrade"
	"github.com/dejo1307/augur/internal/walk"
	"github.com/dejo1307/augur/pkg/finding"
)

// Exit codes, which are part of the interface: a CI job branches on these.
const (
	ExitClean    = 0 // nothing hidden found
	ExitFindings = 1 // findings present
	ExitError    = 2 // could not read or parse the file
)

// parseAnywhere parses flags that may appear before, after or between the paths,
// and returns the paths.
//
// Go's flag package stops at the first argument that is not a flag, so
// `augur scan photo.jpg --json` hands `--json` to the scanner as a filename and
// reports that no such file exists. Every form documented in the README and on
// the site does that, which makes this a bug in the tool rather than in the
// documentation: nobody types the flags first because nothing else requires it.
//
// The loop is the standard way round it — parse, take the first operand, parse
// what is left — and it keeps flags with separate values (`-o out.jpg`) working,
// because those are still consumed in flag position.
func parseAnywhere(fs *flag.FlagSet, args []string) ([]string, error) {
	var operands []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return operands, nil
		}
		operands = append(operands, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

// Scan implements `augur scan PATH... [--json] [--min-severity=...]`.
//
// One file is one question and the report answers it in full. A directory is a
// different question — what is in this repository, and what did you not look at —
// so it gets a different report rather than the file report repeated a thousand
// times. Both go through the same engine on the same terms; only the path source
// and the rendering differ.
func Scan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "write findings as JSON")
	// Empty rather than "notice": the default depends on the target, and the two
	// cases are resolved below. A file the user named deserves everything found;
	// a repository needs a floor or the one alarm drowns in trailing whitespace.
	minSev := fs.String("min-severity", "", "notice, concern or alarm (default: notice for a file, concern for a directory)")
	maxSize := fs.Int64("max-size", walk.DefaultMaxSize, "when walking a directory, skip files larger than this many bytes")
	noGit := fs.Bool("no-git", false, "walk the filesystem instead of asking git which files the repository has")
	maxFiles := fs.Int("max-files", 20, "how many flagged files the text report details (0 for all)")
	paths, err := parseAnywhere(fs, args)
	if err != nil {
		return ExitError
	}
	if len(paths) == 0 {
		fmt.Fprintln(stderr, "usage: augur scan PATH... [--json] [--min-severity=notice|concern|alarm]")
		return ExitError
	}

	if len(paths) == 1 && isRegularFile(paths[0]) {
		return scanFile(paths[0], *minSev, *asJSON, stdout, stderr)
	}
	return scanTree(paths, treeOptions{
		minSev:   *minSev,
		asJSON:   *asJSON,
		maxSize:  *maxSize,
		noGit:    *noGit,
		maxFiles: *maxFiles,
	}, stdout, stderr)
}

// scanFile is the single-file report, unchanged: one file, every finding, and
// the JSON shape other programs already parse.
func scanFile(path, minSev string, asJSON bool, stdout, stderr io.Writer) int {
	if minSev == "" {
		minSev = "notice"
	}
	threshold, err := parseSeverity(minSev)
	if err != nil {
		fmt.Fprintln(stderr, "augur:", err)
		return ExitError
	}

	s, err := session.Open(path)
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
	if asJSON {
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

type treeOptions struct {
	minSev   string
	asJSON   bool
	maxSize  int64
	noGit    bool
	maxFiles int
}

// scanTree scans every file under the given roots.
func scanTree(roots []string, opt treeOptions, stdout, stderr io.Writer) int {
	// A repository floor of `concern`, for the reason `agents` has one: notice-level
	// trailing whitespace and byte-order marks are a linter's business, and across a
	// few thousand files they bury the single decoded payload that is this tool's
	// entire reason to exist. The floor is stated in the report and lifted by
	// --min-severity=notice.
	if opt.minSev == "" {
		opt.minSev = "concern"
	}
	threshold, err := parseSeverity(opt.minSev)
	if err != nil {
		fmt.Fprintln(stderr, "augur:", err)
		return ExitError
	}

	ctx := context.Background()
	var paths []string
	var skipped []report.TreeSkip
	sources := map[walk.Source]bool{}
	seen := map[string]bool{}

	for _, root := range roots {
		res, err := walk.Walk(ctx, root, walk.Options{MaxSize: opt.maxSize, NoGit: opt.noGit})
		if err != nil {
			fmt.Fprintln(stderr, "augur:", err)
			return ExitError
		}
		sources[res.Source] = true
		for _, p := range res.Files {
			if seen[p] {
				continue // overlapping arguments name the same file once
			}
			seen[p] = true
			paths = append(paths, p)
		}
		for _, s := range res.Skipped {
			skipped = append(skipped, report.TreeSkip{Path: s.Path, Reason: s.Reason})
		}
	}

	result := report.TreeResult{
		Root:      strings.Join(roots, ", "),
		Source:    sourceLabel(sources),
		Threshold: threshold,
		MaxSize:   opt.maxSize,
		Files:     scanAll(paths, threshold),
		Skipped:   skipped,
		MaxFiles:  opt.maxFiles,
	}

	render := report.Tree
	if opt.asJSON {
		render = report.TreeJSON
	}
	if err := render(stdout, result); err != nil {
		fmt.Fprintln(stderr, "augur:", err)
		return ExitError
	}

	// Same contract as a single file: a scan that could not complete is an error,
	// never a clean bill of health.
	failed, found := false, false
	for _, f := range result.Files {
		if f.Err != nil {
			failed = true
		}
		if len(f.Findings) > 0 {
			found = true
		}
	}
	switch {
	case failed:
		return ExitError
	case found:
		return ExitFindings
	}
	return ExitClean
}

// scanAll scans paths concurrently and returns the results in path order.
//
// A scan is pure over a file's bytes — it reads no shared state and writes none —
// so the only thing concurrency costs here is determinism, and indexing the
// results by position buys that back. Memory is bounded by the worker count times
// the walk's size limit rather than by the size of the repository.
func scanAll(paths []string, threshold finding.Severity) []report.TreeFile {
	out := make([]report.TreeFile, len(paths))
	workers := runtime.GOMAXPROCS(0)
	if workers > len(paths) {
		workers = len(paths)
	}
	if workers < 1 {
		return out
	}

	queue := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range queue {
				out[i] = scanOne(paths[i], threshold)
			}
		}()
	}
	for i := range paths {
		queue <- i
	}
	close(queue)
	wg.Wait()
	return out
}

func scanOne(path string, threshold finding.Severity) report.TreeFile {
	entry := report.TreeFile{Path: path}
	s, err := session.Open(path)
	if err != nil {
		entry.Err = err
		return entry
	}
	entry.Format = string(s.Result.Source.Format)
	entry.Examined = s.Result.Examined()
	if len(s.Result.Errors) > 0 {
		// The findings that did come back are kept and reported, but the file is
		// marked incomplete: a detector that failed makes "nothing else here" a
		// claim nobody checked.
		entry.Err = errors.Join(s.Result.Errors...)
	}
	all := s.Findings()
	entry.Findings = atLeast(all, threshold)
	entry.Suppressed = len(all) - len(entry.Findings)
	return entry
}

// sourceLabel names how the file list was produced. Several roots can answer
// differently — one inside a repository, one not — and the report says so rather
// than picking the more flattering of the two.
func sourceLabel(sources map[walk.Source]bool) string {
	if len(sources) == 1 {
		for s := range sources {
			return string(s)
		}
	}
	return "mixed"
}

func isRegularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// Clean implements `augur clean FILE [-o OUT] [--categories=...] [--force]`.
func Clean(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("clean", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("o", "", "destination (default: alongside the original, with .clean before the extension)")
	cats := fs.String("categories", "", "only remove these categories, comma-separated (default: everything removable)")
	force := fs.Bool("force", false, "overwrite the destination if it exists")
	paths, err := parseAnywhere(fs, args)
	if err != nil {
		return ExitError
	}
	if len(paths) != 1 {
		fmt.Fprintln(stderr, "usage: augur clean FILE [-o OUT] [--categories=invisible,metadata] [--force]")
		return ExitError
	}

	s, err := session.Open(paths[0])
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
				if f.Kind == agents.Config && len(entry.Findings) > 0 {
					entry.Raw = s.Original
				}
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
