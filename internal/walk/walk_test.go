package walk

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func write(t *testing.T, path, content string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func names(root string, paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		rel, err := filepath.Rel(root, p)
		if err != nil {
			rel = p
		}
		out = append(out, filepath.ToSlash(rel))
	}
	return out
}

func has(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func reasonFor(res Result, root, rel string) string {
	for _, s := range res.Skipped {
		if r, err := filepath.Rel(root, s.Path); err == nil && filepath.ToSlash(r) == rel {
			return s.Reason
		}
	}
	return ""
}

func TestWalkSkipsVendoredDirectories(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "main.go"), "package main\n")
	write(t, filepath.Join(root, "node_modules", "left-pad", "index.js"), "module.exports = 1\n")
	write(t, filepath.Join(root, ".git", "config"), "[core]\n")
	write(t, filepath.Join(root, ".github", "workflows", "ci.yml"), "name: CI\n")

	res, err := Walk(context.Background(), root, Options{NoGit: true})
	if err != nil {
		t.Fatal(err)
	}
	got := names(root, res.Files)
	if !has(got, "main.go") || !has(got, ".github/workflows/ci.yml") {
		t.Errorf("expected the source and the workflow, got %v", got)
	}
	// A dot directory is not automatically uninteresting: .github holds files a
	// repository ships. Only the named build and dependency directories go.
	for _, unwanted := range []string{"node_modules/left-pad/index.js", ".git/config"} {
		if has(got, unwanted) {
			t.Errorf("walked into %s", unwanted)
		}
	}
}

func TestWalkReportsWhatItDidNotOpen(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "small.txt"), "hello\n")
	write(t, filepath.Join(root, "big.txt"), strings.Repeat("x", 2048))

	res, err := Walk(context.Background(), root, Options{NoGit: true, MaxSize: 1024})
	if err != nil {
		t.Fatal(err)
	}
	if got := names(root, res.Files); len(got) != 1 || got[0] != "small.txt" {
		t.Fatalf("expected only the small file, got %v", got)
	}
	// The point of the whole package: a file that was passed over is reported as
	// passed over, never silently absent from a report that then reads as clean.
	if r := reasonFor(res, root, "big.txt"); r != ReasonTooLarge {
		t.Errorf("big.txt skip reason = %q, want %q", r, ReasonTooLarge)
	}
}

func TestWalkDoesNotFollowSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need a privilege on Windows")
	}
	root := t.TempDir()
	outside := t.TempDir()
	write(t, filepath.Join(outside, "secret.txt"), "elsewhere\n")
	write(t, filepath.Join(root, "real.txt"), "here\n")
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}

	res, err := Walk(context.Background(), root, Options{NoGit: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range res.Files {
		if strings.Contains(p, "secret.txt") {
			t.Fatalf("followed a symlink out of the tree: %v", res.Files)
		}
	}
	if r := reasonFor(res, root, "link"); r != ReasonSymlink {
		t.Errorf("link skip reason = %q, want %q", r, ReasonSymlink)
	}
}

func TestWalkOnAFileReturnsThatFileUncapped(t *testing.T) {
	root := t.TempDir()
	p := write(t, filepath.Join(root, "big.txt"), strings.Repeat("x", 4096))

	res, err := Walk(context.Background(), p, Options{MaxSize: 16})
	if err != nil {
		t.Fatal(err)
	}
	// A path named on the command line is scanned whatever its size. The cap is
	// there to bound a walk, not to overrule the user.
	if len(res.Files) != 1 || res.Files[0] != p {
		t.Fatalf("Walk(file) = %v, want just %s", res.Files, p)
	}
	if len(res.Skipped) != 0 {
		t.Errorf("skipped %v", res.Skipped)
	}
}

func TestWalkMissingRootIsAnError(t *testing.T) {
	if _, err := Walk(context.Background(), filepath.Join(t.TempDir(), "nope"), Options{}); err == nil {
		t.Fatal("expected an error for a path that is not there")
	}
}

// git returns a repository with one tracked file, one untracked file and one
// ignored file, or skips the test where git is unavailable.
func gitRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not on PATH")
	}
	root := t.TempDir()
	write(t, filepath.Join(root, ".gitignore"), "ignored.txt\nbuilt/\n")
	write(t, filepath.Join(root, "tracked.txt"), "tracked\n")
	write(t, filepath.Join(root, "untracked.txt"), "untracked\n")
	write(t, filepath.Join(root, "ignored.txt"), "ignored\n")
	write(t, filepath.Join(root, "built", "artifact.js"), "built\n")

	for _, args := range [][]string{
		{"init", "-q"},
		{"add", "tracked.txt", ".gitignore"},
	} {
		cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Skipf("git %v: %v: %s", args, err, out)
		}
	}
	return root
}

func TestWalkAsksGitInsideARepository(t *testing.T) {
	root := gitRepo(t)

	res, err := Walk(context.Background(), root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != Git {
		t.Fatalf("Source = %q, want %q", res.Source, Git)
	}
	got := names(root, res.Files)
	for _, want := range []string{"tracked.txt", "untracked.txt", ".gitignore"} {
		if !has(got, want) {
			t.Errorf("expected %s in %v", want, got)
		}
	}
	// The whole reason for shelling out: .gitignore is honoured exactly, nested
	// rules and all, without this package implementing any of it.
	for _, unwanted := range []string{"ignored.txt", "built/artifact.js"} {
		if has(got, unwanted) {
			t.Errorf("scanned %s, which .gitignore excludes", unwanted)
		}
	}
	if has(got, ".git/config") {
		t.Errorf("scanned the git directory itself: %v", got)
	}
}

func TestWalkNoGitIgnoresTheIgnoreRules(t *testing.T) {
	root := gitRepo(t)

	res, err := Walk(context.Background(), root, Options{NoGit: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != Filesystem {
		t.Fatalf("Source = %q, want %q", res.Source, Filesystem)
	}
	if got := names(root, res.Files); !has(got, "ignored.txt") {
		t.Errorf("--no-git should reach an ignored file, got %v", got)
	}
}
