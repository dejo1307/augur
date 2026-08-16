// Package session holds what it means for a user to be looking at a file: the
// bytes, the findings, what is currently selected, and the write that follows.
//
// Everything stateful lives here, so the viewer and the CLI can be two thin
// presentations of the same object rather than two implementations of the same
// behaviour. Neither of them touches file bytes.
package session

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dejo1307/augur/internal/scan"
	"github.com/dejo1307/augur/pkg/finding"
)

// MaxFileSize caps what will be read into memory. Generous, and present so that
// pointing the tool at a disk image fails with a sentence rather than an OOM.
const MaxFileSize = 256 << 20 // 256 MiB

// Session is one file, open.
type Session struct {
	Path     string
	Original []byte
	Result   scan.Result

	selected map[finding.ID]bool
}

// Open reads a file and scans it. The file is opened read-only and is never
// reopened for writing: cleaning writes a new path. See Save.
func Open(path string) (*Session, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%s is a directory", path)
	}
	if info.Size() > MaxFileSize {
		return nil, fmt.Errorf("%s is %d bytes, larger than the %d byte limit",
			path, info.Size(), MaxFileSize)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s := &Session{
		Path:     path,
		Original: data,
		Result:   scan.Scan(path, data),
		selected: map[finding.ID]bool{},
	}
	// Everything removable starts selected. The common case is "take out what you
	// found", and the notable case — leaving something in — is the one worth a
	// deliberate keystroke.
	for _, f := range s.Removable() {
		s.selected[f.ID] = true
	}
	return s, nil
}

// Findings is everything found, most severe first.
func (s *Session) Findings() finding.Set { return s.Result.Findings }

// Removable is the subset that can actually be taken out of this file.
func (s *Session) Removable() finding.Set {
	return scan.Removable(s.Result.Source.Format, s.Result.Findings)
}

// Selected reports whether a finding is marked for removal.
func (s *Session) Selected(id finding.ID) bool { return s.selected[id] }

// Toggle flips a finding's selection. Findings that cannot be removed cannot be
// selected, so the viewer never offers a choice that would fail on save.
func (s *Session) Toggle(id finding.ID) {
	for _, f := range s.Removable() {
		if f.ID == id {
			s.selected[id] = !s.selected[id]
			return
		}
	}
}

// SelectAll and SelectNone move the whole removable set at once.
func (s *Session) SelectAll() {
	for _, f := range s.Removable() {
		s.selected[f.ID] = true
	}
}

func (s *Session) SelectNone() { s.selected = map[finding.ID]bool{} }

// SelectionIDs is the current selection, in finding order so a clean is
// deterministic.
func (s *Session) SelectionIDs() []finding.ID {
	var out []finding.ID
	for _, f := range s.Result.Findings {
		if s.selected[f.ID] {
			out = append(out, f.ID)
		}
	}
	return out
}

// SelectionCount is how many findings are marked for removal.
func (s *Session) SelectionCount() int { return len(s.SelectionIDs()) }

// Preview returns what the cleaned file would be, without writing anything.
func (s *Session) Preview() ([]byte, error) {
	return scan.Apply(s.Result.Source, s.Result.Findings, s.SelectionIDs())
}

// Verification is the result of re-scanning what was just written.
//
// The tool's central claim is that it removed what it said it removed. This is
// where that claim is checked rather than asserted — against the bytes on disk,
// after the write, by the same scanner that found them in the first place.
type Verification struct {
	Path string
	// Removed is how many findings the clean was supposed to take out.
	Removed int
	// Remaining is what a fresh scan of the written file still finds.
	Remaining finding.Set
	// Leaked lists findings that were selected for removal and are still there.
	// It should always be empty. If it is not, the tool says so rather than
	// reporting success.
	Leaked finding.Set
}

// OK reports whether the written file is what was promised.
func (v Verification) OK() bool { return len(v.Leaked) == 0 }

func (v Verification) String() string {
	if v.OK() {
		return fmt.Sprintf("verified: %d removed, %d finding(s) deliberately left in place",
			v.Removed, len(v.Remaining))
	}
	return fmt.Sprintf("VERIFICATION FAILED: %d finding(s) selected for removal are still in %s",
		len(v.Leaked), v.Path)
}

// ErrWouldOverwrite reports a destination that already exists.
var ErrWouldOverwrite = errors.New("destination already exists")

// Save writes the cleaned copy to `dest` and then re-reads it to check the result.
//
// It refuses to write over the file it read. That is not a convenience check: the
// entire safety story is that the original is still there to compare against, and
// a tool that can be talked into destroying its own evidence does not have one.
func (s *Session) Save(dest string, overwrite bool) (Verification, error) {
	if sameFile(dest, s.Path) {
		return Verification{}, fmt.Errorf("refusing to overwrite the file being inspected (%s)", s.Path)
	}
	if !overwrite {
		if _, err := os.Stat(dest); err == nil {
			return Verification{}, fmt.Errorf("%w: %s", ErrWouldOverwrite, dest)
		}
	}

	cleaned, err := s.Preview()
	if err != nil {
		return Verification{}, err
	}
	if err := os.WriteFile(dest, cleaned, 0o644); err != nil {
		return Verification{}, err
	}

	// Re-read from disk rather than re-scanning the buffer. Checking the bytes
	// that actually landed is the only version of this check worth running.
	written, err := os.ReadFile(dest)
	if err != nil {
		return Verification{}, fmt.Errorf("wrote %s but could not read it back: %w", dest, err)
	}

	after := scan.Scan(dest, written)
	v := Verification{Path: dest, Removed: s.SelectionCount(), Remaining: after.Findings}

	// A selected finding has leaked if something with the same kind and the same
	// content is still present. Offsets shift when earlier bytes are removed, so
	// identity cannot be compared directly.
	gone := map[string]int{}
	for _, f := range after.Findings {
		gone[string(f.Kind)+"\x00"+f.Label]++
	}
	for _, id := range s.SelectionIDs() {
		for _, f := range s.Result.Findings {
			if f.ID != id {
				continue
			}
			key := string(f.Kind) + "\x00" + f.Label
			if gone[key] > 0 {
				gone[key]--
				v.Leaked = append(v.Leaked, f)
			}
		}
	}
	return v, nil
}

// DefaultDest is where a cleaned copy goes when the user does not say: beside the
// original, with ".clean" before the extension.
func DefaultDest(path string) string {
	dir, base := filepath.Dir(path), filepath.Base(path)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	return filepath.Join(dir, stem+".clean"+ext)
}

// sameFile compares two paths by identity where possible, so a symlink or a
// different spelling of the same path is still caught.
func sameFile(a, b string) bool {
	ai, err := os.Stat(a)
	if err != nil {
		// a does not exist yet, so it cannot be b. Fall back to a path compare in
		// case of a stat error for another reason.
		if abs, err := filepath.Abs(a); err == nil {
			if babs, err := filepath.Abs(b); err == nil {
				return abs == babs
			}
		}
		return false
	}
	bi, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(ai, bi)
}
