package c2pa

import (
	"strings"
	"testing"
)

// appendStore puts a manifest store at the end of `body` and gives it a data hash
// over everything before it — the arrangement every producer uses, reduced to the
// part the binding check cares about.
//
// It settles the store's own length by iteration, because the exclusion range in
// the assertion names that length and CBOR encodes a bigger number in more bytes.
// One pass would produce a store whose claim describes a store of a different
// size, which is not a thing any real producer emits.
func appendStore(t *testing.T, body []byte, build func(hash map[string]any) []byte) ([]byte, Extent) {
	t.Helper()
	size := 0
	for pass := 0; pass < 6; pass++ {
		padded := append(append([]byte{}, body...), make([]byte, size)...)
		store := build(dataHash(padded, [2]int{len(body), len(body) + size}))
		if len(store) == size {
			return append(append([]byte{}, body...), store...), Extent{Offset: len(body), Length: size}
		}
		size = len(store)
	}
	t.Fatal("the store's length never settled")
	return nil, Extent{}
}

func buildSignedFile(t *testing.T, content string, claim map[string]any) ([]byte, Extent) {
	t.Helper()
	if claim == nil {
		claim = map[string]any{"claim_generator": "test 1.0"}
	}
	return appendStore(t, []byte(content), func(hash map[string]any) []byte {
		return buildStore(t, manifestOptions{
			claim:      claim,
			assertions: map[string]any{labelDataHash: hash},
		})
	})
}

func TestBindingMatchesAnUntouchedFile(t *testing.T) {
	file, at := buildSignedFile(t, "the quick brown fox\n", nil)
	report := Read(file[at.Offset:], file, at)
	if report.Err != nil {
		t.Fatal(report.Err)
	}
	if report.Binding.Status != BindingMatches {
		t.Fatalf("binding = %s (%s)", report.Binding.Status, report.Binding.Note)
	}
	if report.Mismatched() {
		t.Error("an untouched file was reported as changed")
	}
}

func TestBindingCatchesAChangedByte(t *testing.T) {
	file, at := buildSignedFile(t, "the quick brown fox\n", nil)
	file[3] = 'X' // one byte, inside the hashed range

	report := Read(file[at.Offset:], file, at)
	if !report.Mismatched() {
		t.Fatalf("a changed byte went unreported: %s", report.Binding.Status)
	}
	if report.Binding.Expected == "" || report.Binding.Actual == "" {
		t.Error("a mismatch should say which two hashes differ")
	}
}

func TestBindingIsNotCheckedWhenTheExclusionsDoNotCoverTheManifest(t *testing.T) {
	// A claim whose exclusions do not contain the manifest is not describing the
	// file in front of us. Hashing anyway produces a confident mismatch about a
	// file nobody has touched — the one outcome this check must never produce.
	file, at := buildSignedFile(t, "content here\n", nil)
	short := Extent{Offset: at.Offset, Length: at.Length + 1}

	report := Read(file[at.Offset:], append(file, 0x00), short)
	if report.Binding.Status != BindingUnchecked {
		t.Fatalf("binding = %s, want unchecked", report.Binding.Status)
	}
	if !strings.Contains(report.Binding.Note, "exclusions do not cover") {
		t.Errorf("note = %q", report.Binding.Note)
	}
}

func TestBindingNamesTheHashTypesItDoesNotCompute(t *testing.T) {
	// A box hash and a BMFF hash are real bindings computed a different way.
	// Silence about them would read as "no binding"; a claim to have checked them
	// would be false.
	for _, label := range []string{labelBoxHash, labelBMFFHash, labelCollectionHash} {
		store := buildStore(t, manifestOptions{
			claim:      map[string]any{"claim_generator": "test 1.0"},
			assertions: map[string]any{label: map[string]any{"alg": "sha256"}},
		})
		s, err := Parse(store)
		if err != nil {
			t.Fatal(err)
		}
		b := s.Verify([]byte("whatever"), []Extent{{Offset: 0, Length: 1}})
		if b.Status != BindingUnchecked || b.Kind != label {
			t.Errorf("%s: %s / %s", label, b.Status, b.Kind)
		}
	}
}

func TestBindingRefusesAlgorithmsItCannotCompute(t *testing.T) {
	body := []byte("content\n")
	store := buildStore(t, manifestOptions{
		claim: map[string]any{"claim_generator": "test 1.0"},
		assertions: map[string]any{labelDataHash: map[string]any{
			"alg":        "sha3-256",
			"hash":       make([]byte, 32),
			"exclusions": []any{map[string]any{"start": 0, "length": len(body)}},
		}},
	})
	report := Read(store, body, Extent{Offset: 0, Length: len(body)})
	if report.Binding.Status != BindingUnchecked {
		t.Fatalf("binding = %s", report.Binding.Status)
	}
	if !strings.Contains(report.Binding.Note, "sha3-256") {
		t.Errorf("the note should name the algorithm; got %q", report.Binding.Note)
	}
}

func TestAnIngredientsBindingIsNotCheckedAgainstThisFile(t *testing.T) {
	// The store's earlier manifests describe the assets this one was made from.
	// Their hashes are over those assets, so checking one here would report a
	// mismatch about a file that is intact.
	body := []byte("the file's own content\n")
	ingredient := superBox("urn:uuid:ingredient", uuidManifest,
		superBox(labelAssertions, uuidAssertion,
			superBox(labelDataHash, uuidCBOR, contentBox(boxCBOR,
				cborEncode(dataHash([]byte("a completely different asset")))))),
		superBox(labelClaim, uuidClaim, contentBox(boxCBOR,
			cborEncodeIndefinite(map[string]any{"claim_generator": "the ingredient's tool"}))))

	file, at := appendStore(t, body, func(hash map[string]any) []byte {
		return superBox(labelStore, uuidStore, ingredient, activeManifest(hash))
	})
	store := file[at.Offset:]

	report := Read(store, file, at)
	if report.Binding.Status != BindingMatches {
		t.Fatalf("binding = %s (%s)", report.Binding.Status, report.Binding.Note)
	}
}

func activeManifest(hash map[string]any) []byte {
	return superBox("urn:uuid:active", uuidManifest,
		superBox(labelAssertions, uuidAssertion,
			superBox(labelDataHash, uuidCBOR, contentBox(boxCBOR, cborEncode(hash)))),
		superBox(labelClaim, uuidClaim, contentBox(boxCBOR,
			cborEncodeIndefinite(map[string]any{"claim_generator": "this file's tool"}))))
}
