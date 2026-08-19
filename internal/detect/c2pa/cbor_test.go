package c2pa

import (
	"strings"
	"testing"
)

func TestCBORReadsBothLengthForms(t *testing.T) {
	// A claim written by the CBOR library most producers use arrives in the
	// indefinite-length form. A decoder that handles only the definite form reads
	// every assertion and no claim, which is silent and total.
	want := map[string]any{"claim_generator": "tool 1.0", "alg": "sha256"}

	for _, tc := range []struct {
		name  string
		bytes []byte
	}{
		{"definite", cborEncode(want)},
		{"indefinite", cborEncodeIndefinite(want)},
	} {
		got, err := cborDecode(tc.bytes)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if cborString(cborGet(got, "claim_generator")) != "tool 1.0" {
			t.Errorf("%s: claim_generator did not survive: %v", tc.name, got)
		}
	}
}

func TestCBORRefusesInputItCannotSatisfy(t *testing.T) {
	// Every one of these is a length that the input does not have behind it. A
	// decoder that trusts the declaration allocates or reads past the end, on
	// bytes chosen by whoever wrote the file.
	for name, input := range map[string][]byte{
		"byte string longer than the input": {0x58, 0xff, 0x01, 0x02},
		"array of a million items":          {0x9a, 0x00, 0x0f, 0x42, 0x40},
		"map of a million pairs":            {0xba, 0x00, 0x0f, 0x42, 0x40},
		"truncated head":                    {0x1b, 0x00},
		"break with nothing open":           {0xff},
	} {
		if _, err := cborDecode(input); err == nil {
			t.Errorf("%s: decoded without complaint", name)
		}
	}
}

func TestCBORRefusesUnboundedNesting(t *testing.T) {
	// A file that nests arrays a thousand deep is not a manifest; it is an
	// attempt to walk the stack down inside a tool people run on files they do
	// not trust.
	deep := make([]byte, 0, 1024)
	for i := 0; i < 1024; i++ {
		deep = append(deep, 0x81) // array of one
	}
	deep = append(deep, 0x01)
	if _, err := cborDecode(deep); err == nil {
		t.Fatal("a thousand levels of nesting decoded without complaint")
	}
}

func TestCBORKeepsIntegerAndTextKeysApart(t *testing.T) {
	// COSE headers are keyed by integer: 1 is the algorithm, 33 is the
	// certificate chain. Folding those into strings would make header 1
	// indistinguishable from a header called "1".
	raw := []byte{0xa2, 0x01, 0x26, 0x61, '1', 0x02}
	v, err := cborDecode(raw)
	if err != nil {
		t.Fatal(err)
	}
	m := cborMap(v)
	if alg, ok := cborInt(m[int64(1)]); !ok || alg != -7 {
		t.Errorf("integer key 1 = %v, want -7", m[int64(1)])
	}
	if n, ok := cborInt(m["1"]); !ok || n != 2 {
		t.Errorf("text key \"1\" = %v, want 2", m["1"])
	}
}

func TestCBORRejectsTrailingBytes(t *testing.T) {
	raw := append(cborEncode("hello"), 0x01)
	if _, err := cborDecode(raw); err == nil || !strings.Contains(err.Error(), "left over") {
		t.Fatalf("trailing byte accepted: %v", err)
	}
}
