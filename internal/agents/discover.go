package agents

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dejo1307/augur/internal/walk"
)

// Found is one instruction file located on disk.
type Found struct {
	Agent Agent
	Scope Scope
	Kind  Kind
	// Path is absolute.
	Path string
	// Why is the source's explanation of what reads this file.
	Why string
}

// Install is an agent that is present, with the instruction files it owns.
type Install struct {
	Agent Agent
	// Installed is false for an agent with no marker that was nonetheless
	// matched by its files — the AGENTS.md convention, mainly.
	Installed bool
	Files     []Found
}

// Roots are the two places to look. Both are explicit rather than read from the
// environment inside this package, so the whole of discovery can be tested
// against a temporary tree.
type Roots struct {
	Home    string
	Project string
}

// DefaultRoots resolves the home directory and uses dir as the project root.
func DefaultRoots(dir string) (Roots, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Roots{}, err
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return Roots{}, err
	}
	return Roots{Home: home, Project: abs}, nil
}

// maxMatches bounds what one glob may return. A `**` pattern pointed at an
// unexpectedly large tree should degrade to a truncated answer, not to a hang.
const maxMatches = 5000

// Discover finds every instruction file for every agent in the catalogue.
//
// An agent is reported when it has an installation marker OR when any of its
// files exist. Both halves matter: a marker with no files says "installed, and
// it reads nothing yet", and files with no marker say "this repository carries
// instructions for a tool you do not have" — which is worth seeing, because the
// file still arrives with a clone and will be read by whoever does have it.
func Discover(roots Roots) []Install {
	var out []Install
	seen := map[string]bool{} // absolute path -> already attributed

	for _, agent := range Catalog() {
		inst := Install{Agent: agent, Installed: installed(roots.Home, agent)}

		for _, src := range agent.Sources {
			root := roots.Home
			if src.Scope == Project {
				root = roots.Project
			}
			if root == "" {
				continue
			}
			for _, p := range glob(root, src.Glob) {
				if seen[p] {
					continue // first agent to claim a shared file keeps it
				}
				seen[p] = true
				inst.Files = append(inst.Files, Found{
					Agent: agent, Scope: src.Scope, Kind: src.Kind, Path: p, Why: src.Why,
				})
			}
		}

		if inst.Installed || len(inst.Files) > 0 {
			sort.Slice(inst.Files, func(i, j int) bool { return inst.Files[i].Path < inst.Files[j].Path })
			out = append(out, inst)
		}
	}
	return out
}

// installed reports whether any of an agent's markers exist.
func installed(home string, a Agent) bool {
	for _, m := range a.Markers {
		if _, err := os.Stat(filepath.Join(home, filepath.FromSlash(m))); err == nil {
			return true
		}
	}
	return false
}

// glob expands a pattern under root, returning absolute paths to regular files.
//
// filepath.Glob has no `**`, and the layouts here need it: a Claude Code plugin
// skill lives at an unpredictable depth under .claude/plugins. Rather than take
// a dependency for one operator, the pattern is matched segment by segment, with
// `**` consuming any number of segments including none.
func glob(root, pattern string) []string {
	segments := strings.Split(pattern, "/")
	var out []string
	expand(root, segments, &out)

	sort.Strings(out)
	if len(out) > maxMatches {
		out = out[:maxMatches]
	}
	return out
}

func expand(dir string, segments []string, out *[]string) {
	if len(*out) >= maxMatches {
		return
	}
	if len(segments) == 0 {
		return
	}

	head, rest := segments[0], segments[1:]

	if head == "**" {
		// Zero segments: try the remainder right here.
		expand(dir, rest, out)
		// One or more: recurse into every subdirectory, keeping `**` in play.
		for _, e := range readDirs(dir) {
			expand(filepath.Join(dir, e), segments, out)
		}
		return
	}

	// A literal segment with no wildcard: skip the directory listing entirely.
	// This is what keeps a pattern like `.claude/projects/*/memory/*.md` cheap
	// on a tree with thousands of unrelated files.
	if !strings.ContainsAny(head, "*?[") {
		next := filepath.Join(dir, head)
		if len(rest) == 0 {
			if isFile(next) {
				*out = append(*out, next)
			}
			return
		}
		expand(next, rest, out)
		return
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		ok, err := filepath.Match(head, e.Name())
		if err != nil || !ok {
			continue
		}
		next := filepath.Join(dir, e.Name())
		if len(rest) == 0 {
			if !e.IsDir() {
				*out = append(*out, next)
			}
			continue
		}
		if e.IsDir() {
			expand(next, rest, out)
		}
	}
}

// readDirs lists the subdirectories a `**` walk may descend into.
//
// The exclusions live in walk.SkipDirs, shared with the directory scanner rather
// than kept here twice. This matters most for the project-scoped `**/CLAUDE.md`
// patterns: a nested CLAUDE.md is loaded when work happens in its directory, so
// the pattern has to be recursive — but without that list it would walk
// node_modules and .git on every run, which is both slow and a good way to
// report a vendored dependency's instruction file as if it were yours.
func readDirs(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() || walk.SkipDir(e.Name()) {
			continue
		}
		// Do not follow symlinks: an agent directory containing a link to / would
		// otherwise turn discovery into a filesystem-wide walk.
		if e.Type()&fs.ModeSymlink != 0 {
			continue
		}
		out = append(out, e.Name())
	}
	return out
}

func isFile(p string) bool {
	info, err := os.Lstat(p)
	return err == nil && info.Mode().IsRegular()
}

// Count totals the files across a discovery result.
func Count(installs []Install) int {
	n := 0
	for _, i := range installs {
		n += len(i.Files)
	}
	return n
}
