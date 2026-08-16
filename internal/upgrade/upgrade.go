// Package upgrade replaces the running augur binary with the newest published
// release.
//
// It sits in the surface layer beside internal/cli, because it is the
// implementation of a command rather than anything the scanner knows about — no
// package below this one may import it, and it imports none of them.
//
// The security posture is the same as install.sh's, for the same reason: this
// downloads an executable and puts it on the user's PATH. The checksum is
// verified before anything is written, and the replacement is a rename, so a
// failed or tampered download can never leave a half-written binary behind.
package upgrade

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	repoSlug = "dejo1307/augur"

	// maxAsset bounds what will be pulled into memory. A release archive is a
	// couple of megabytes; anything approaching this is not one.
	maxAsset = 128 << 20
)

// Endpoints, as variables rather than constants so the tests can point the whole
// upgrade path at a local server. That is the difference between testing the
// checksum helper and testing that a tampered download never reaches the disk.
var (
	apiBase      = "https://api.github.com"
	downloadBase = "https://github.com"
)

func latestURL() string {
	return fmt.Sprintf("%s/repos/%s/releases/latest", apiBase, repoSlug)
}

func assetURL(version, name string) string {
	return fmt.Sprintf("%s/%s/releases/download/v%s/%s", downloadBase, repoSlug, version, name)
}

// ErrNoRelease reports that the project has no published release at all. It is a
// distinct error because it is not a failure the user can act on by retrying —
// and right after a project is created it is the answer everyone gets.
var ErrNoRelease = errors.New("no published release found")

// DevVersion is the version string of a binary built from source rather than
// installed from a release.
const DevVersion = "dev"

// supported mirrors the release workflow's build matrix. Kept here so an
// unsupported platform gets a sentence instead of a 404.
var supported = map[string]bool{
	"linux/amd64":   true,
	"linux/arm64":   true,
	"darwin/amd64":  true,
	"darwin/arm64":  true,
	"windows/amd64": true,
}

// Result describes what an upgrade check found.
type Result struct {
	Current string
	Latest  string
	// Newer reports whether Latest is actually ahead of Current.
	Newer bool
	// Dev reports that the running binary was built from source, so there is no
	// meaningful version to compare and an upgrade would replace it with a
	// release build.
	Dev bool
}

// Check asks what the newest release is, and changes nothing.
func Check(ctx context.Context, current string) (Result, error) {
	latest, err := latestVersion(ctx)
	if err != nil {
		return Result{}, err
	}
	r := Result{
		Current: current,
		Latest:  latest,
		Dev:     current == DevVersion || current == "",
	}
	r.Newer = r.Dev || Compare(latest, strings.TrimPrefix(current, "v")) > 0
	return r, nil
}

// Run upgrades the running binary in place, reporting progress to w.
func Run(ctx context.Context, current string, w io.Writer, force bool) error {
	platform := runtime.GOOS + "/" + runtime.GOARCH
	if !supported[platform] {
		return fmt.Errorf("no published build for %s — see https://github.com/%s/releases", platform, repoSlug)
	}

	res, err := Check(ctx, current)
	if err != nil {
		return err
	}
	if !res.Newer && !force {
		fmt.Fprintf(w, "augur %s is already the latest release.\n", current)
		return nil
	}
	if res.Dev {
		fmt.Fprintf(w, "This build reports version %q, so it was built from source.\n", current)
		fmt.Fprintf(w, "Upgrading will replace it with the published v%s.\n", res.Latest)
	}

	names := assetNames(res.Latest, runtime.GOOS, runtime.GOARCH)

	fmt.Fprintf(w, "==> Downloading augur v%s for %s ...\n", res.Latest, platform)
	tarball, err := download(ctx, assetURL(res.Latest, names.Archive))
	if err != nil {
		return err
	}
	sums, err := download(ctx, assetURL(res.Latest, names.Checksum))
	if err != nil {
		return err
	}

	fmt.Fprintln(w, "==> Verifying checksum ...")
	if err := VerifyChecksum(tarball, sums, names.Archive); err != nil {
		return err
	}

	binary, err := ExtractBinary(tarball, names.Binary)
	if err != nil {
		return err
	}

	fmt.Fprintln(w, "==> Replacing the current binary ...")
	if err := replaceExecutable(binary); err != nil {
		return err
	}

	fmt.Fprintf(w, "==> augur is now v%s\n", res.Latest)
	return nil
}

// ---------------------------------------------------------------------------
// version comparison
// ---------------------------------------------------------------------------

// Compare orders two dotted version strings. It returns -1, 0 or 1 for a < b,
// a == b and a > b.
//
// Deliberately not a full semver implementation: releases here are plain
// major.minor.patch, and the one thing that matters is that 0.10.0 sorts above
// 0.9.0 — which a string comparison gets wrong, and which is the whole reason
// this function exists rather than `latest != current`.
func Compare(a, b string) int {
	as := strings.Split(strings.TrimPrefix(a, "v"), ".")
	bs := strings.Split(strings.TrimPrefix(b, "v"), ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		x := part(as, i)
		y := part(bs, i)
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// part returns the i-th dotted component as a number, or 0 when absent or
// unparseable — so "1.2" and "1.2.0" compare equal, and a trailing pre-release
// tag degrades to "same as the release" rather than to an error.
func part(parts []string, i int) int {
	if i >= len(parts) {
		return 0
	}
	s := parts[i]
	if j := strings.IndexAny(s, "-+"); j >= 0 {
		s = s[:j]
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

// ---------------------------------------------------------------------------
// release assets
// ---------------------------------------------------------------------------

// Assets are the file names a release publishes for one platform.
type Assets struct {
	Binary   string // the file inside the archive
	Archive  string
	Checksum string
}

// assetNames mirrors the naming in .github/workflows/release.yml. The two must
// agree; a mismatch shows up as a 404 at upgrade time rather than at build time,
// which is why the shape is stated in one function instead of inline.
func assetNames(version, goos, goarch string) Assets {
	base := fmt.Sprintf("augur-%s-%s-%s", version, goos, goarch)
	bin := base
	if goos == "windows" {
		bin += ".exe"
	}
	return Assets{Binary: bin, Archive: base + ".tar.gz", Checksum: base + ".sha256"}
}

// ---------------------------------------------------------------------------
// fetching
// ---------------------------------------------------------------------------

func latestVersion(ctx context.Context) (string, error) {
	body, err := download(ctx, latestURL())
	if err != nil {
		// GitHub answers 404 both for "no such repository" and for "this
		// repository has never published a release". The second is much more
		// likely and is not an error the user should have to decode from a
		// status line.
		if errors.Is(err, errNotFound) {
			return "", fmt.Errorf("%w for %s", ErrNoRelease, repoSlug)
		}
		return "", fmt.Errorf("asking GitHub for the latest release: %w", err)
	}
	var rel struct {
		TagName string `json:"tag_name"`
	}
	if err := json.Unmarshal(body, &rel); err != nil {
		return "", fmt.Errorf("reading the release metadata: %w", err)
	}
	v := strings.TrimPrefix(rel.TagName, "v")
	if v == "" {
		return "", ErrNoRelease
	}
	return v, nil
}

// errNotFound distinguishes a 404 from any other transport failure.
var errNotFound = errors.New("not found")

func download(ctx context.Context, url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "augur-upgrade")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%w: %s", errNotFound, url)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxAsset))
}

// VerifyChecksum checks the archive against the published sha256 file.
//
// The sum file is `sha256sum` output: "<hex>  <filename>". The filename is
// checked too, so a sum file for a different platform's archive is rejected
// rather than silently compared against the wrong bytes.
func VerifyChecksum(tarball, sumFile []byte, wantName string) error {
	fields := strings.Fields(string(sumFile))
	if len(fields) < 1 {
		return errors.New("checksum file is empty")
	}
	want := strings.ToLower(fields[0])
	if len(fields) >= 2 {
		got := strings.TrimPrefix(fields[1], "*") // sha256sum marks binary mode with a leading *
		if got != wantName {
			return fmt.Errorf("checksum file is for %q, expected %q", got, wantName)
		}
	}

	sum := sha256.Sum256(tarball)
	if have := hex.EncodeToString(sum[:]); have != want {
		return fmt.Errorf("checksum mismatch: archive is %s, expected %s — refusing to install", have, want)
	}
	return nil
}

// ExtractBinary pulls one named file out of a gzipped tar.
//
// By name, not by position: release archives also carry LICENSE and NOTICE, and
// taking "the first regular file" would install the license over the binary.
func ExtractBinary(tarball []byte, want string) ([]byte, error) {
	gz, err := gzip.NewReader(strings.NewReader(string(tarball)))
	if err != nil {
		return nil, fmt.Errorf("reading the archive: %w", err)
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading the archive: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		// Compare on the base name: an archive built elsewhere may carry a path.
		if filepath.Base(hdr.Name) != want {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(tr, maxAsset))
		if err != nil {
			return nil, err
		}
		if len(data) == 0 {
			return nil, fmt.Errorf("%s in the archive is empty", want)
		}
		return data, nil
	}
	return nil, fmt.Errorf("the archive does not contain %s", want)
}

// ---------------------------------------------------------------------------
// replacing the running binary
// ---------------------------------------------------------------------------

func replaceExecutable(binary []byte) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locating the current executable: %w", err)
	}
	// Follow symlinks so an upgrade replaces the real file rather than the link
	// a package manager or `ln -s` put on the PATH.
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return replaceAt(exe, binary)
}

// replaceAt is the half of the upgrade that touches the disk, separated from
// locating the running executable so it can be exercised against a temporary
// path instead of the test binary.
func replaceAt(exe string, binary []byte) error {
	// Stage the new binary in the SAME directory as the old one, so the final
	// step is a rename within one filesystem — atomic, and impossible to
	// interrupt into a half-written executable.
	dir := filepath.Dir(exe)
	tmp, err := os.CreateTemp(dir, ".augur-upgrade-*")
	if err != nil {
		return permHint(dir, err)
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(binary); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, 0o755); err != nil {
		return err
	}

	if runtime.GOOS == "windows" {
		// Windows will not let a running .exe be overwritten, but it will let it
		// be renamed. Move it aside, put the new one in place, then try to remove
		// the old one — that last step legitimately fails while the old process is
		// still running, and the next upgrade clears it.
		old := exe + ".old"
		_ = os.Remove(old)
		if err := os.Rename(exe, old); err != nil {
			return permHint(dir, err)
		}
		if err := os.Rename(tmpPath, exe); err != nil {
			_ = os.Rename(old, exe) // roll back
			return permHint(dir, err)
		}
		cleanup = false
		_ = os.Remove(old)
		return nil
	}

	if err := os.Rename(tmpPath, exe); err != nil {
		return permHint(dir, err)
	}
	cleanup = false
	return nil
}

// permHint turns the commonest failure — augur installed somewhere the user
// cannot write — into something actionable rather than a bare EACCES.
func permHint(dir string, err error) error {
	if errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("cannot write to %s: %w\n"+
			"Re-run with elevated permissions, or re-install:\n"+
			"  curl -fsSL https://raw.githubusercontent.com/%s/main/install.sh | sh",
			dir, err, repoSlug)
	}
	return err
}
