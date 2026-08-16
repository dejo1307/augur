package upgrade

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeRelease stands in for GitHub: the latest-release API plus the download
// endpoints, serving assets named exactly as the release workflow names them.
type fakeRelease struct {
	version string
	assets  map[string][]byte
	// corrupt rewrites the archive after its checksum was computed, standing in
	// for a tampered or truncated download.
	corrupt bool
}

func (f *fakeRelease) start(t *testing.T) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/releases/latest") {
			if f.version == "" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			fmt.Fprintf(w, `{"tag_name":"v%s"}`, f.version)
			return
		}
		name := filepath.Base(r.URL.Path)
		data, ok := f.assets[name]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if f.corrupt && strings.HasSuffix(name, ".tar.gz") {
			data = append(append([]byte{}, data...), []byte("tampered")...)
		}
		_, _ = w.Write(data)
	}))
	t.Cleanup(srv.Close)

	oldAPI, oldDL := apiBase, downloadBase
	apiBase, downloadBase = srv.URL, srv.URL
	t.Cleanup(func() { apiBase, downloadBase = oldAPI, oldDL })
}

// newFakeRelease builds a complete, self-consistent release for this platform.
func newFakeRelease(t *testing.T, version string, payload []byte) *fakeRelease {
	t.Helper()
	names := assetNames(version, runtime.GOOS, runtime.GOARCH)
	archive := releaseArchive(t, names.Binary, payload)
	return &fakeRelease{
		version: version,
		assets: map[string][]byte{
			names.Archive:  archive,
			names.Checksum: sumFileFor(archive, names.Archive),
		},
	}
}

func TestCheckReportsANewerRelease(t *testing.T) {
	newFakeRelease(t, "2.0.0", []byte("new binary")).start(t)

	res, err := Check(context.Background(), "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Newer {
		t.Error("2.0.0 should be newer than 1.0.0")
	}
	if res.Latest != "2.0.0" {
		t.Errorf("Latest = %q, want 2.0.0", res.Latest)
	}
	if res.Dev {
		t.Error("a numbered build should not be reported as a dev build")
	}
}

func TestCheckReportsUpToDate(t *testing.T) {
	newFakeRelease(t, "1.0.0", []byte("x")).start(t)

	res, err := Check(context.Background(), "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if res.Newer {
		t.Error("1.0.0 should not be newer than itself")
	}
}

func TestCheckTreatsADevBuildAsUpgradable(t *testing.T) {
	newFakeRelease(t, "1.0.0", []byte("x")).start(t)

	res, err := Check(context.Background(), DevVersion)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Dev || !res.Newer {
		t.Errorf("a %q build should be flagged as dev and upgradable, got %+v", DevVersion, res)
	}
}

// The state every user is in before the first tag is pushed. It must produce a
// sentence, not a bare HTTP status.
func TestCheckWithNoPublishedRelease(t *testing.T) {
	(&fakeRelease{}).start(t)

	_, err := Check(context.Background(), "1.0.0")
	if err == nil {
		t.Fatal("expected an error when no release is published")
	}
	if !errors.Is(err, ErrNoRelease) {
		t.Errorf("error should be ErrNoRelease, got: %v", err)
	}
	if strings.Contains(err.Error(), "404") {
		t.Errorf("error should not leak a raw status line: %v", err)
	}
}

// The whole path: check, download, verify, extract, replace.
func TestRunReplacesTheBinary(t *testing.T) {
	payload := []byte("\x7fELF the new augur")
	newFakeRelease(t, "2.0.0", payload).start(t)

	dir := t.TempDir()
	exe := filepath.Join(dir, "augur")
	if err := os.WriteFile(exe, []byte("the old augur"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Run() resolves the real executable, so drive the disk-touching half
	// directly with the same bytes the download produced.
	res, err := Check(context.Background(), "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	names := assetNames(res.Latest, runtime.GOOS, runtime.GOARCH)
	archive, err := download(context.Background(), assetURL(res.Latest, names.Archive))
	if err != nil {
		t.Fatal(err)
	}
	sums, err := download(context.Background(), assetURL(res.Latest, names.Checksum))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyChecksum(archive, sums, names.Archive); err != nil {
		t.Fatal(err)
	}
	binary, err := ExtractBinary(archive, names.Binary)
	if err != nil {
		t.Fatal(err)
	}
	if err := replaceAt(exe, binary); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("binary at %s is %q, want %q", exe, got, payload)
	}
	info, err := os.Stat(exe)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Errorf("replacement is not executable: mode %v", info.Mode())
	}

	// The staging temp file must not be left behind next to the binary.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		names := []string{}
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("upgrade left files behind: %v", names)
	}
}

// A tampered download must abort before anything is written.
func TestRunRefusesATamperedDownload(t *testing.T) {
	fake := newFakeRelease(t, "2.0.0", []byte("new binary"))
	fake.corrupt = true
	fake.start(t)

	var out bytes.Buffer
	err := Run(context.Background(), "1.0.0", &out, false)
	if err == nil {
		t.Fatal("upgraded from a tampered archive")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("expected a checksum failure, got: %v", err)
	}
	if strings.Contains(out.String(), "augur is now") {
		t.Error("reported success despite refusing the download")
	}
}

func TestRunIsANoOpWhenCurrent(t *testing.T) {
	newFakeRelease(t, "1.0.0", []byte("x")).start(t)

	var out bytes.Buffer
	if err := Run(context.Background(), "1.0.0", &out, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "already the latest") {
		t.Errorf("output = %q, want an already-latest message", out.String())
	}
	if strings.Contains(out.String(), "Downloading") {
		t.Error("downloaded an upgrade it did not need")
	}
}

func TestReplaceAtIsAtomicOnFailure(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "augur")
	original := []byte("the old augur")
	if err := os.WriteFile(exe, original, 0o755); err != nil {
		t.Fatal(err)
	}

	// A directory that cannot be written to: the original must survive intact.
	ro := filepath.Join(dir, "readonly")
	if err := os.Mkdir(ro, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(ro, 0o700) })

	if err := replaceAt(filepath.Join(ro, "augur"), []byte("new")); err == nil {
		t.Skip("this environment permits writing to a mode-0500 directory (likely running as root)")
	}

	got, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Error("a failed upgrade elsewhere disturbed the existing binary")
	}
}
