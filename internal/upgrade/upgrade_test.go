package upgrade

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.1", "1.0.0", 1},
		{"1.0.0", "1.0.1", -1},
		{"1.1.0", "1.0.9", 1},
		{"2.0.0", "1.99.99", 1},
		{"v1.2.3", "1.2.3", 0}, // a leading v is not a difference
		{"1.2", "1.2.0", 0},    // a missing component is zero
		{"1.2.0", "1.2", 0},

		// The case a string comparison gets wrong, and the reason this function
		// exists: "0.10.0" < "0.9.0" lexically, but 10 > 9.
		{"0.10.0", "0.9.0", 1},
		{"0.9.0", "0.10.0", -1},
		{"1.20.0", "1.3.0", 1},

		// A pre-release tag degrades to its release rather than erroring.
		{"1.2.3-rc1", "1.2.3", 0},
		{"1.2.3+build7", "1.2.3", 0},
	}
	for _, tc := range cases {
		if got := Compare(tc.a, tc.b); got != tc.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestAssetNamesMatchTheReleaseWorkflow(t *testing.T) {
	// These strings are a contract with .github/workflows/release.yml. If that
	// file's naming changes and this does not, upgrade 404s at runtime — so the
	// expected values are written out literally rather than derived.
	got := assetNames("0.4.1", "linux", "amd64")
	want := Assets{
		Binary:   "augur-0.4.1-linux-amd64",
		Archive:  "augur-0.4.1-linux-amd64.tar.gz",
		Checksum: "augur-0.4.1-linux-amd64.sha256",
	}
	if got != want {
		t.Errorf("assetNames = %+v, want %+v", got, want)
	}

	win := assetNames("0.4.1", "windows", "amd64")
	if win.Binary != "augur-0.4.1-windows-amd64.exe" {
		t.Errorf("windows binary = %q, want the .exe suffix", win.Binary)
	}
	if strings.HasSuffix(win.Archive, ".exe.tar.gz") {
		t.Errorf("archive name picked up the .exe suffix: %q", win.Archive)
	}
}

func TestSupportedPlatformsMatchTheBuildMatrix(t *testing.T) {
	// Keep in sync with the matrix in .github/workflows/release.yml.
	for _, p := range []string{
		"linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64", "windows/amd64",
	} {
		if !supported[p] {
			t.Errorf("%s is built by the release workflow but not marked supported", p)
		}
	}
	if len(supported) != 5 {
		t.Errorf("supported has %d entries, the build matrix has 5", len(supported))
	}
}

// releaseArchive builds a tarball shaped exactly like a real release asset:
// the binary plus LICENSE and NOTICE.
func releaseArchive(t *testing.T, binaryName string, binary []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	add := func(name string, data []byte) {
		t.Helper()
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o755, Size: int64(len(data)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	// LICENSE first, deliberately: a reader that took "the first regular file"
	// would install the license text over the binary.
	add("LICENSE", []byte("Apache License\nVersion 2.0\n"))
	add("NOTICE", []byte("augur\n"))
	add(binaryName, binary)

	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestExtractBinaryPicksTheBinaryNotTheLicense(t *testing.T) {
	want := []byte("\x7fELF pretend this is a binary")
	archive := releaseArchive(t, "augur-1.0.0-linux-amd64", want)

	got, err := ExtractBinary(archive, "augur-1.0.0-linux-amd64")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("extracted %q, want %q", got, want)
	}
}

func TestExtractBinaryRejectsAnArchiveWithoutIt(t *testing.T) {
	archive := releaseArchive(t, "augur-1.0.0-linux-amd64", []byte("x"))
	if _, err := ExtractBinary(archive, "augur-1.0.0-darwin-arm64"); err == nil {
		t.Fatal("extracted a binary that is not in the archive")
	}
}

func TestExtractBinaryRejectsGarbage(t *testing.T) {
	if _, err := ExtractBinary([]byte("not a gzip stream"), "augur"); err == nil {
		t.Fatal("accepted something that is not an archive")
	}
}

func sumFileFor(data []byte, name string) []byte {
	s := sha256.Sum256(data)
	return []byte(fmt.Sprintf("%s  %s\n", hex.EncodeToString(s[:]), name))
}

func TestVerifyChecksumAcceptsAMatch(t *testing.T) {
	archive := []byte("pretend tarball")
	name := "augur-1.0.0-linux-amd64.tar.gz"
	if err := VerifyChecksum(archive, sumFileFor(archive, name), name); err != nil {
		t.Fatal(err)
	}
}

// The one that matters: a tampered archive must be refused. install.sh has the
// same guarantee, and both exist because this path puts an executable on PATH.
func TestVerifyChecksumRejectsTampering(t *testing.T) {
	archive := []byte("pretend tarball")
	name := "augur-1.0.0-linux-amd64.tar.gz"
	sums := sumFileFor(archive, name)

	tampered := append(append([]byte{}, archive...), []byte(" plus a payload")...)
	err := VerifyChecksum(tampered, sums, name)
	if err == nil {
		t.Fatal("accepted an archive whose checksum does not match")
	}
	if !strings.Contains(err.Error(), "refusing to install") {
		t.Errorf("error should say it refused to install, got: %v", err)
	}
}

// A sum file for a different platform must not be compared against these bytes.
func TestVerifyChecksumRejectsAMismatchedName(t *testing.T) {
	archive := []byte("pretend tarball")
	sums := sumFileFor(archive, "augur-1.0.0-darwin-arm64.tar.gz")
	if err := VerifyChecksum(archive, sums, "augur-1.0.0-linux-amd64.tar.gz"); err == nil {
		t.Fatal("accepted a checksum file belonging to a different asset")
	}
}

func TestVerifyChecksumRejectsAnEmptySumFile(t *testing.T) {
	if err := VerifyChecksum([]byte("x"), nil, "a.tar.gz"); err == nil {
		t.Fatal("accepted an empty checksum file")
	}
}

// A sum file written by `shasum -a 256 -b` marks binary mode with a leading '*'
// on the filename; that must not read as a name mismatch.
func TestVerifyChecksumAcceptsBinaryModeMarker(t *testing.T) {
	archive := []byte("pretend tarball")
	name := "augur-1.0.0-linux-amd64.tar.gz"
	s := sha256.Sum256(archive)
	sums := []byte(fmt.Sprintf("%s *%s\n", hex.EncodeToString(s[:]), name))
	if err := VerifyChecksum(archive, sums, name); err != nil {
		t.Errorf("rejected a binary-mode checksum line: %v", err)
	}
}
