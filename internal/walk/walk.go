// Package walk turns a path a user typed into the list of files augur will look
// at — and, just as deliberately, the list of the ones it will not.
//
// Scanning one file is a question about that file. Scanning a repository is a
// question about coverage, and the answer is only worth anything if the tool can
// say what it left out. So a walk returns both halves: the files, and every path
// it decided against with the reason it decided.
package walk

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// DefaultMaxSize caps a file found by walking a tree, as opposed to one the user
// named. It is far below session.MaxFileSize on purpose: a directory scan reads
// files concurrently, so the ceiling is per worker, and nothing that hides a
// smuggled instruction in text is ten megabytes long.
const DefaultMaxSize = 10 << 20 // 10 MiB

// Options tune a walk. The zero value is the default behaviour.
type Options struct {
	// MaxSize skips larger files, reporting them. Zero means DefaultMaxSize.
	MaxSize int64
	// NoGit forces the filesystem walk even inside a repository.
	NoGit bool
}

// Source records how the file list was produced, because it changes what the
// list means: git's answer honours every .gitignore, the filesystem's honours a
// fixed list of directory names.
type Source string

const (
	Git        Source = "git"
	Filesystem Source = "filesystem"
)

// Skip is a path the walk found and did not hand over, with why.
//
// Reasons are drawn from a small fixed set so a report can group by them.
type Skip struct {
	Path   string
	Reason string
}

// The reasons, fixed so the report can count them.
const (
	ReasonTooLarge   = "larger than the size limit"
	ReasonSymlink    = "symbolic link, not followed"
	ReasonSubmodule  = "submodule, scan it separately"
	ReasonUnreadable = "could not be read"
)

// Result is one walk.
type Result struct {
	Root    string
	Source  Source
	Files   []string
	Skipped []Skip
}

// Walk lists the files under root.
//
// A root that is a regular file is returned as itself, uncapped and unfiltered:
// the user named that file, and a tool that silently declines to look at a path
// it was pointed at directly is worse than useless.
func Walk(ctx context.Context, root string, opt Options) (Result, error) {
	if opt.MaxSize <= 0 {
		opt.MaxSize = DefaultMaxSize
	}

	info, err := os.Lstat(root)
	if err != nil {
		return Result{}, err
	}
	res := Result{Root: root, Source: Filesystem}
	if !info.IsDir() {
		res.Files = []string{root}
		return res, nil
	}

	var candidates []string
	if !opt.NoGit {
		if list, err := gitFiles(ctx, root); err == nil {
			candidates, res.Source = list, Git
		}
	}
	if res.Source != Git {
		candidates, res.Skipped = fsFiles(root)
	}

	for _, p := range candidates {
		info, err := os.Lstat(p)
		switch {
		case os.IsNotExist(err):
			// Tracked in the index and deleted from the worktree. There are no
			// bytes to look at, and nothing was passed over.
			continue
		case err != nil:
			res.Skipped = append(res.Skipped, Skip{p, ReasonUnreadable})
		case info.IsDir():
			// git lists a submodule as one entry that is a directory on disk.
			res.Skipped = append(res.Skipped, Skip{p, ReasonSubmodule})
		case info.Mode()&fs.ModeSymlink != 0:
			// A link's target is either inside the tree already or outside it on
			// purpose. Following it is how one scan becomes a scan of the disk.
			res.Skipped = append(res.Skipped, Skip{p, ReasonSymlink})
		case !info.Mode().IsRegular():
			res.Skipped = append(res.Skipped, Skip{p, ReasonUnreadable})
		case info.Size() > opt.MaxSize:
			res.Skipped = append(res.Skipped, Skip{p, ReasonTooLarge})
		default:
			res.Files = append(res.Files, p)
		}
	}

	sort.Strings(res.Files)
	sort.Slice(res.Skipped, func(i, j int) bool { return res.Skipped[i].Path < res.Skipped[j].Path })
	return res, nil
}

// gitFiles asks git which files are in the repository at root.
//
// This is a shell-out rather than an implementation of .gitignore, and the
// reason is precedence: ignore rules nest per directory, compose with
// .git/info/exclude and the user's global excludes, and support negation. A
// second implementation of that would be a second set of bugs, and every one of
// them would show up as augur scanning a file the user believed was ignored, or
// skipping one they believed was not. git already knows; ask it.
//
// --cached and --others together are "tracked, plus untracked and not ignored",
// which is the set a person means by "the files in this repository".
func gitFiles(ctx context.Context, root string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "git", "-C", root,
		"ls-files", "--cached", "--others", "--exclude-standard", "-z")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-files: %w: %s", err, strings.TrimSpace(stderr.String()))
	}

	seen := map[string]bool{}
	var files []string
	for _, name := range strings.Split(string(out), "\x00") {
		if name == "" {
			continue
		}
		// -z means the names are raw bytes, never quoted, so a path with a
		// newline or a quote in it arrives intact.
		p := filepath.Join(root, filepath.FromSlash(name))
		if seen[p] {
			continue // an unmerged path appears once per stage
		}
		seen[p] = true
		files = append(files, p)
	}
	return files, nil
}

// fsFiles walks the tree directly, for a directory that is not in a repository
// or a run that asked for it. It skips the directory names in SkipDirs and
// nothing else — no extension list, because a name is a claim and the format is
// sniffed from the bytes anyway.
func fsFiles(root string) ([]string, []Skip) {
	var files []string
	var skipped []Skip

	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			skipped = append(skipped, Skip{p, ReasonUnreadable})
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if p != root && SkipDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		files = append(files, p)
		return nil
	})
	return files, skipped
}

// skipDirs are directory names a walk never descends into. Read through SkipDir
// rather than exported, so the list cannot be rewritten from another package.
//
// It is a blunt list and it is meant to be: these are directories whose contents
// belong to somebody else — a package manager, a build, a cache — and reporting a
// vendored dependency's hidden characters as if they were yours is noise that
// buries the finding that is. Inside a repository git's ignore rules do this job
// properly and this list is not consulted at all.
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true,
	"dist": true, "build": true, "target": true, "out": true,
	".venv": true, "venv": true, "site-packages": true, "__pycache__": true,
	".next": true, ".nuxt": true, ".svelte-kit": true, ".turbo": true,
	".gradle": true, ".terraform": true, "Pods": true, "DerivedData": true,
	".cache": true, ".enola": true,
}

// SkipDir reports whether a directory of this name is walked into.
func SkipDir(name string) bool { return skipDirs[name] }
