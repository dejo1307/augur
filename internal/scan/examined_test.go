package scan_test

import (
	"testing"

	"github.com/dejo1307/augur/internal/scan"
	"github.com/dejo1307/augur/pkg/detect"
)

// TestExaminedMatchesTheHandlers holds Result.Examined to the detector registry
// rather than to a list somebody remembered to update.
//
// A text detector applies to every format and reads whatever regions were
// exposed, so it applies to Binary too; a container detector applies only to the
// formats it parses. "Applies here but not to Binary" therefore identifies a
// structural handler exactly, and a format with one has been looked inside. Text
// is the remaining case: its region is the whole file.
func TestExaminedMatchesTheHandlers(t *testing.T) {
	formats := []detect.Format{
		detect.Unknown, detect.Text, detect.JPEG, detect.PNG, detect.WebP,
		detect.GIF, detect.PDF, detect.Office, detect.Binary,
	}
	for _, f := range formats {
		handled := false
		for _, d := range scan.Detectors() {
			if d.Applies(f) && !d.Applies(detect.Binary) {
				handled = true
			}
		}
		want := handled || f == detect.Text

		res := scan.Result{Source: &detect.Source{Format: f}}
		if got := res.Examined(); got != want {
			t.Errorf("Examined(%s) = %v, want %v — the registry and Examined disagree", f, got, want)
		}
	}
}

// TestUnreadFileIsNotReportedAsClean is the failure this fact exists to prevent:
// a format nothing handles produces no findings, and at repository scale that is
// indistinguishable from a clean file unless the scan says which it was.
func TestUnreadFileIsNotReportedAsClean(t *testing.T) {
	gif := append([]byte("GIF89a"), 0x00, 0x01, 0x02, 0xFF, 0xFE)
	res := scan.Scan("x.gif", gif)

	if !res.Clean() {
		t.Fatalf("expected no findings in a file nothing parses, got %d", len(res.Findings))
	}
	if res.Examined() {
		t.Error("a GIF has no handler, so Examined must be false")
	}
}

func TestExaminedIsTrueForAnImageWithNoMetadata(t *testing.T) {
	// A PNG signature with no text chunks: the container handler walked it and
	// legitimately found nothing, which is a different answer from "unread".
	png := append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 32)...)
	res := scan.Scan("x.png", png)
	if !res.Examined() {
		t.Error("a PNG has a handler, so Examined must be true even with nothing found")
	}
}
