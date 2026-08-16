package agents

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("instructions\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// roots builds an isolated home and project tree. Discovery never reads the
// environment itself, which is what makes this possible.
func roots(t *testing.T) Roots {
	t.Helper()
	dir := t.TempDir()
	return Roots{Home: filepath.Join(dir, "home"), Project: filepath.Join(dir, "proj")}
}

func paths(installs []Install) []string {
	var out []string
	for _, i := range installs {
		for _, f := range i.Files {
			out = append(out, f.Path)
		}
	}
	return out
}

func contains(list []string, suffix string) bool {
	for _, s := range list {
		if strings.HasSuffix(s, filepath.FromSlash(suffix)) {
			return true
		}
	}
	return false
}

func TestDiscoverFindsGlobalAndProjectFiles(t *testing.T) {
	r := roots(t)
	write(t, filepath.Join(r.Home, ".claude", "CLAUDE.md"))
	write(t, filepath.Join(r.Project, "CLAUDE.md"))
	write(t, filepath.Join(r.Project, ".github", "copilot-instructions.md"))

	got := paths(Discover(r))
	for _, want := range []string{
		".claude/CLAUDE.md",
		"proj/CLAUDE.md",
		".github/copilot-instructions.md",
	} {
		if !contains(got, want) {
			t.Errorf("did not find %s in %v", want, got)
		}
	}
}

// The pattern that needs `**`: a plugin skill sits at an unpredictable depth.
func TestDiscoverWalksNestedPluginTrees(t *testing.T) {
	r := roots(t)
	deep := filepath.Join(r.Home, ".claude", "plugins", "marketplaces", "official",
		"plugins", "some-plugin", "skills", "a-skill", "SKILL.md")
	write(t, deep)

	if got := paths(Discover(r)); !contains(got, "a-skill/SKILL.md") {
		t.Errorf("** did not reach a nested plugin skill; found %v", got)
	}
}

// Auto-memory is loaded into context every session, so it must be covered.
func TestDiscoverFindsAutoMemory(t *testing.T) {
	r := roots(t)
	write(t, filepath.Join(r.Home, ".claude", "projects", "-Users-x-proj", "memory", "MEMORY.md"))

	installs := Discover(r)
	if got := paths(installs); !contains(got, "memory/MEMORY.md") {
		t.Fatalf("did not find auto-memory; found %v", got)
	}
	for _, i := range installs {
		for _, f := range i.Files {
			if strings.HasSuffix(f.Path, "MEMORY.md") && !strings.Contains(f.Why, "each session") {
				t.Errorf("auto-memory should say it is loaded each session, got %q", f.Why)
			}
		}
	}
}

// A file must be attributed to exactly one agent, or it gets scanned twice and
// counted twice.
func TestSharedFilesAreAttributedOnce(t *testing.T) {
	r := roots(t)
	write(t, filepath.Join(r.Project, "AGENTS.md"))
	write(t, filepath.Join(r.Home, ".claude")+string(filepath.Separator)+"CLAUDE.md")

	seen := map[string]int{}
	for _, p := range paths(Discover(r)) {
		seen[p]++
	}
	for p, n := range seen {
		if n > 1 {
			t.Errorf("%s was attributed %d times", p, n)
		}
	}
}

func TestInstalledMarkerIsReportedWithoutFiles(t *testing.T) {
	r := roots(t)
	if err := os.MkdirAll(filepath.Join(r.Home, ".cursor"), 0o755); err != nil {
		t.Fatal(err)
	}

	var cursor *Install
	for i := range Discover(r) {
		if Discover(r)[i].Agent.ID == "cursor" {
			cursor = &Discover(r)[i]
		}
	}
	if cursor == nil {
		t.Fatal("an installed agent with no instruction files should still be reported")
	}
	if !cursor.Installed {
		t.Error("marker directory exists but Installed is false")
	}
}

// Instructions for a tool you do not have still matter: they arrive with a clone
// and will be read by whoever does have it.
func TestFilesWithoutAnInstallAreStillReported(t *testing.T) {
	r := roots(t)
	write(t, filepath.Join(r.Project, ".windsurfrules"))

	var found bool
	for _, i := range Discover(r) {
		if i.Agent.ID == "windsurf" {
			found = true
			if i.Installed {
				t.Error("windsurf is not installed in this tree but was reported as installed")
			}
			if len(i.Files) != 1 {
				t.Errorf("expected the rules file, got %d files", len(i.Files))
			}
		}
	}
	if !found {
		t.Error("a project file for an uninstalled agent was dropped")
	}
}

func TestDiscoverIgnoresDirectoriesMatchingAFilePattern(t *testing.T) {
	r := roots(t)
	// A directory named like the file we want must not be reported as a file.
	if err := os.MkdirAll(filepath.Join(r.Project, "CLAUDE.md"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, p := range paths(Discover(r)) {
		if strings.HasSuffix(p, filepath.FromSlash("proj/CLAUDE.md")) {
			t.Error("reported a directory as an instruction file")
		}
	}
}

// A symlink loop inside an agent directory must not turn discovery into a walk
// of the whole filesystem.
func TestGlobDoesNotFollowSymlinks(t *testing.T) {
	dir := t.TempDir()
	deep := filepath.Join(dir, "a", "b")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(dir, filepath.Join(deep, "loop")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	write(t, filepath.Join(deep, "SKILL.md"))

	done := make(chan []string, 1)
	go func() { done <- glob(dir, "**/SKILL.md") }()

	select {
	case got := <-done:
		if len(got) != 1 {
			t.Errorf("expected exactly one match, got %d: %v", len(got), got)
		}
	case <-timeout(t):
		t.Fatal("glob followed a symlink loop and did not terminate")
	}
}

func TestGlobMatchesSingleSegmentWildcards(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "rules", "one.md"))
	write(t, filepath.Join(dir, "rules", "two.md"))
	write(t, filepath.Join(dir, "rules", "nested", "three.md"))

	got := glob(dir, "rules/*.md")
	if len(got) != 2 {
		t.Errorf("`*` should not cross a separator: got %v", got)
	}
}

func TestCatalogEntriesAreWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, a := range Catalog() {
		if a.ID == "" || a.Name == "" {
			t.Errorf("agent with an empty ID or name: %+v", a)
		}
		if seen[a.ID] {
			t.Errorf("duplicate agent ID %q", a.ID)
		}
		seen[a.ID] = true
		if len(a.Sources) == 0 {
			t.Errorf("%s has no sources", a.ID)
		}
		for _, s := range a.Sources {
			if s.Scope != Global && s.Scope != Project {
				t.Errorf("%s: bad scope %q", a.ID, s.Scope)
			}
			// Every source explains what reads it; the report shows that line
			// beside a finding, and without it a finding has no consequence.
			if s.Why == "" {
				t.Errorf("%s: source %q has no explanation", a.ID, s.Glob)
			}
			if strings.HasPrefix(s.Glob, "/") || strings.Contains(s.Glob, "..") {
				t.Errorf("%s: glob %q must be relative and must not escape its root", a.ID, s.Glob)
			}
		}
	}
}

// timeout gives the symlink test a bound without pulling in a time import at
// the top of a file that otherwise does not need one.
func timeout(t *testing.T) <-chan struct{} {
	t.Helper()
	ch := make(chan struct{})
	go func() {
		time.Sleep(10 * time.Second)
		close(ch)
	}()
	return ch
}

// A skill is a directory. Its SKILL.md says "see references/foo.md" and the
// model goes and reads that file, so covering only SKILL.md misses most of what
// a skill actually puts into context.
func TestDiscoverFindsSkillSupportFiles(t *testing.T) {
	r := roots(t)
	skill := filepath.Join(r.Home, ".claude", "skills", "helper")
	write(t, filepath.Join(skill, "SKILL.md"))
	write(t, filepath.Join(skill, "references", "palette.md"))

	got := paths(Discover(r))
	if !contains(got, "helper/SKILL.md") {
		t.Error("missed SKILL.md")
	}
	if !contains(got, "references/palette.md") {
		t.Error("missed a skill's supporting reference file")
	}
}

// A CLAUDE.md in a subdirectory is loaded when work happens there, so the one
// that matters is often not at the root.
func TestDiscoverFindsNestedProjectInstructions(t *testing.T) {
	r := roots(t)
	write(t, filepath.Join(r.Project, "services", "api", "CLAUDE.md"))
	write(t, filepath.Join(r.Project, "packages", "web", "AGENTS.md"))

	got := paths(Discover(r))
	if !contains(got, "services/api/CLAUDE.md") {
		t.Error("missed a nested CLAUDE.md")
	}
	if !contains(got, "packages/web/AGENTS.md") {
		t.Error("missed a nested AGENTS.md")
	}
}

// The recursive project patterns must not descend into vendored trees: it is
// slow, and a dependency's instruction file is not yours.
func TestDiscoverSkipsVendoredTrees(t *testing.T) {
	r := roots(t)
	write(t, filepath.Join(r.Project, "CLAUDE.md"))
	for _, skip := range []string{"node_modules", ".git", "vendor", "dist", ".venv"} {
		write(t, filepath.Join(r.Project, skip, "pkg", "CLAUDE.md"))
	}

	got := paths(Discover(r))
	for _, p := range got {
		for _, skip := range []string{"node_modules", ".git", "vendor", "dist", ".venv"} {
			if strings.Contains(p, string(filepath.Separator)+skip+string(filepath.Separator)) {
				t.Errorf("descended into %s: %s", skip, p)
			}
		}
	}
	if !contains(got, "proj/CLAUDE.md") {
		t.Error("the project's own CLAUDE.md was lost along with the skipped trees")
	}
}
