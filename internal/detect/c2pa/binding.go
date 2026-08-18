package c2pa

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"sort"
)

// The hard binding is the part of a Content Credential that is about the bytes
// rather than about the story. The claim carries a hash over the asset, with the
// manifest's own bytes excluded, and signs it. Recomputing that hash needs
// nothing but the file: no vendor key, no network, no trust list. Either the
// bytes still hash to what the claim says, or the file changed after it was
// signed.
//
// That is the whole reason this is worth implementing. Every other provenance
// question — is this signer real, is the certificate trusted, was the timestamp
// honest — needs something augur does not have. This one does not.

// BindingStatus is what could be established about the binding.
type BindingStatus string

const (
	// BindingAbsent: the manifest carries no hard binding at all.
	BindingAbsent BindingStatus = "absent"
	// BindingMatches: the bytes hash to what the claim says they should.
	BindingMatches BindingStatus = "matches"
	// BindingMismatch: they do not. The file is not the file that was signed.
	BindingMismatch BindingStatus = "mismatch"
	// BindingUnchecked: a binding is present in a form augur does not verify.
	// Reported as its own answer rather than folded into either of the others —
	// "we did not check" and "we checked and it was fine" are different facts.
	BindingUnchecked BindingStatus = "unchecked"
)

// Extent locates the manifest's own bytes within the file that carries it: a
// JPEG's APP11 segments, a PNG's caBX chunk, an SVG's manifest element.
//
// It is needed because the check has a precondition worth enforcing. A data hash
// covers the file with the manifest excluded, so the ranges the claim excludes
// must contain the manifest's own bytes. When they do not, augur is not looking
// at the layout the claim was written against — and a hash computed over the
// wrong bytes would report a confident mismatch about a file nobody touched.
type Extent struct{ Offset, Length int }

// Binding is the result of checking a manifest against the file carrying it.
type Binding struct {
	Status BindingStatus
	// Kind is the assertion label the binding came from: "c2pa.hash.data" and so on.
	Kind string
	// Alg is the hash algorithm named by the claim.
	Alg string
	// Note explains an unchecked or mismatched result in one clause.
	Note string
	// Expected and Actual are the first bytes of each hash, for a mismatch. Whole
	// digests are not carried: the question is whether they differ, and a report
	// full of hex helps nobody decide anything.
	Expected, Actual string
}

// Verify checks the active manifest's hard binding against the file it was found
// in. `file` must be the whole file, unmodified: the exclusion ranges in the
// assertion are absolute offsets into it. `carrier` says where the manifest
// itself sits, so the check can refuse to run when the claim's exclusions do not
// describe this file's layout.
func (s *Store) Verify(file []byte, carrier []Extent) Binding {
	m := s.Active()
	if m == nil {
		return Binding{Status: BindingAbsent}
	}

	// The hash types other than a data hash are all real bindings that augur
	// cannot recompute without reproducing the format's own box map, which is a
	// second implementation of the container walkers and a second chance to be
	// subtly wrong. They are named rather than ignored.
	for _, label := range []string{labelBoxHash, labelBMFFHash, labelCollectionHash} {
		if a, ok := m.Assertion(label); ok {
			label = a.Label
			return Binding{
				Status: BindingUnchecked, Kind: label,
				Note: "augur does not recompute this kind of binding",
			}
		}
	}

	a, ok := m.Assertion(labelDataHash)
	if !ok {
		return Binding{Status: BindingAbsent}
	}

	alg := cborString(cborGet(a.Value, "alg"))
	if alg == "" {
		alg = cborString(cborGet(m.Claim, "alg"))
	}
	if alg == "" {
		alg = "sha256" // the specification's default
	}
	h, ok := hasher(alg)
	if !ok {
		return Binding{
			Status: BindingUnchecked, Kind: labelDataHash, Alg: alg,
			Note: fmt.Sprintf("hash algorithm %q is not one augur computes", alg),
		}
	}

	want := cborBytes(cborGet(a.Value, "hash"))
	if len(want) == 0 {
		return Binding{
			Status: BindingUnchecked, Kind: labelDataHash, Alg: alg,
			Note: "the assertion carries no hash",
		}
	}

	ranges, err := exclusions(a.Value, len(file))
	if err != nil {
		return Binding{
			Status: BindingUnchecked, Kind: labelDataHash, Alg: alg,
			Note: err.Error(),
		}
	}

	// The precondition: the claim must have excluded the manifest it arrived in.
	// Every real producer does — the manifest cannot hash itself — so a claim whose
	// exclusions miss it is describing a layout other than the one in front of us.
	if missing, ok := covers(ranges, carrier); !ok {
		return Binding{
			Status: BindingUnchecked, Kind: labelDataHash, Alg: alg,
			Note: fmt.Sprintf("the claim's exclusions do not cover the manifest itself (%d bytes of it at %d are inside the hash)",
				missing.Length, missing.Offset),
		}
	}

	got := hashExcluding(h, file, ranges)
	if len(got) != len(want) {
		return Binding{
			Status: BindingUnchecked, Kind: labelDataHash, Alg: alg,
			Note: fmt.Sprintf("the claim's hash is %d bytes, %s produces %d", len(want), alg, len(got)),
		}
	}
	b := Binding{Kind: labelDataHash, Alg: alg}
	if equalHash(got, want) {
		b.Status = BindingMatches
		return b
	}
	b.Status = BindingMismatch
	b.Expected = short(want)
	b.Actual = short(got)
	return b
}

// exclusions reads the byte ranges the claim left out of its hash — the manifest
// itself, and whatever else the producer had to skip — and returns them sorted
// and merged.
//
// A range that does not fit the file is refused rather than clipped. Clipping
// would let a manifest describing a different file produce a confident "matches"
// or, worse, a confident "mismatch" against a file it was never about.
func exclusions(assertion any, size int) ([][2]int, error) {
	var out [][2]int
	for _, e := range cborArray(cborGet(assertion, "exclusions")) {
		start, ok1 := cborInt(cborGet(e, "start"))
		length, ok2 := cborInt(cborGet(e, "length"))
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("an exclusion range is not a pair of numbers")
		}
		if start < 0 || length < 0 || start+length > int64(size) {
			return nil, fmt.Errorf("an exclusion range lies outside the file")
		}
		if length == 0 {
			continue
		}
		out = append(out, [2]int{int(start), int(start + length)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i][0] < out[j][0] })

	merged := out[:0]
	for _, r := range out {
		if n := len(merged); n > 0 && r[0] <= merged[n-1][1] {
			if r[1] > merged[n-1][1] {
				merged[n-1][1] = r[1]
			}
			continue
		}
		merged = append(merged, r)
	}
	return merged, nil
}

// covers reports whether every byte of the manifest's own bytes falls inside an
// excluded range, and names the first stretch that does not.
func covers(ranges [][2]int, carrier []Extent) (Extent, bool) {
	if len(carrier) == 0 {
		return Extent{}, false
	}
	for _, c := range carrier {
		at := c.Offset
		end := c.Offset + c.Length
		for at < end {
			covered := false
			for _, r := range ranges {
				if at >= r[0] && at < r[1] {
					at = r[1]
					covered = true
					break
				}
			}
			if !covered {
				return Extent{Offset: at, Length: end - at}, false
			}
		}
	}
	return Extent{}, true
}

// hashExcluding hashes the file with the excluded ranges skipped, which is
// exactly what the producer did when it wrote the claim.
func hashExcluding(h hash.Hash, file []byte, ranges [][2]int) []byte {
	at := 0
	for _, r := range ranges {
		if r[0] > at {
			h.Write(file[at:r[0]])
		}
		if r[1] > at {
			at = r[1]
		}
	}
	if at < len(file) {
		h.Write(file[at:])
	}
	return h.Sum(nil)
}

func hasher(alg string) (hash.Hash, bool) {
	switch alg {
	case "sha256":
		return sha256.New(), true
	case "sha384":
		return sha512.New384(), true
	case "sha512":
		return sha512.New(), true
	}
	return nil, false
}

// equalHash compares two digests. Constant time is not called for — both values
// are already in the reader's hands, and there is no secret to leak — but a
// length-checked loop is cheap and keeps the comparison explicit.
func equalHash(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	diff := byte(0)
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func short(digest []byte) string {
	if len(digest) > 6 {
		digest = digest[:6]
	}
	return hex.EncodeToString(digest) + "…"
}
