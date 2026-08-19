package c2pa

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// A C2PA manifest is CBOR most of the way down: the claim, every assertion the
// spec defines, and the COSE signature that binds them. This is the smallest
// decoder that reads all of it.
//
// It is written here rather than pulled in because augur's scanner is standard
// library only — a file inspector that grows a dependency tree is a file
// inspector nobody can audit. The decoder is deliberately strict and bounded: it
// is fed bytes chosen by whoever wrote the file, so every length it reads is
// checked against what is actually there, recursion is capped, and indefinite
// lengths are refused rather than looped over.

var (
	errCBORShort   = errors.New("cbor: input ended mid-value")
	errCBORDeep    = errors.New("cbor: nesting too deep")
	errCBORHuge    = errors.New("cbor: more items than a manifest can plausibly hold")
	errCBORBreak   = errors.New("cbor: break outside an indefinite-length item")
	errCBORTrailer = errors.New("cbor: bytes left over after the value")
)

const (
	cborMaxDepth = 32
	cborMaxItems = 1 << 20
)

// cborBreak is the marker that ends an indefinite-length item. It never escapes
// this file: every place a break can legally appear consumes it.
type cborBreak struct{}

// cborDecode decodes one CBOR value and requires it to be the whole input.
//
// Values map to Go as: unsigned and negative integers to int64 (uint64 when a
// value does not fit), byte strings to []byte, text strings to string, arrays to
// []any, maps to map[any]any, tags to their content, and the simple values to
// bool, nil and float64. Map keys stay as decoded — COSE headers key their maps
// by integer, and rewriting those as strings would lose the distinction between
// header 1 and the string "1".
func cborDecode(b []byte) (any, error) {
	d := &cborDecoder{buf: b}
	v, err := d.value(0)
	if err != nil {
		return nil, err
	}
	if _, isBreak := v.(cborBreak); isBreak {
		return nil, errCBORBreak
	}
	if d.at != len(b) {
		return nil, errCBORTrailer
	}
	return v, nil
}

type cborDecoder struct {
	buf   []byte
	at    int
	items int
}

func (d *cborDecoder) value(depth int) (any, error) {
	if depth > cborMaxDepth {
		return nil, errCBORDeep
	}
	if d.items++; d.items > cborMaxItems {
		return nil, errCBORHuge
	}
	if d.at >= len(d.buf) {
		return nil, errCBORShort
	}
	initial := d.buf[d.at]
	d.at++
	if initial == 0xff {
		return cborBreak{}, nil
	}
	major, minor := initial>>5, initial&0x1f

	// Major type 7 carries the simple values and the floats, whose "argument" is
	// the value itself rather than a length, so it is read before the shared
	// argument path below.
	if major == 7 {
		return d.simple(minor)
	}

	// Indefinite lengths are not exotic here: the CBOR libraries most C2PA
	// producers use write structs as indefinite-length maps, so a decoder that
	// refuses them reads no real claim at all.
	if minor == 31 {
		return d.indefinite(major, depth)
	}

	arg, err := d.argument(minor)
	if err != nil {
		return nil, err
	}

	switch major {
	case 0: // unsigned
		if arg > math.MaxInt64 {
			return arg, nil
		}
		return int64(arg), nil
	case 1: // negative: encodes -1 - arg
		if arg > math.MaxInt64 {
			return nil, fmt.Errorf("cbor: negative integer out of range")
		}
		return -1 - int64(arg), nil
	case 2, 3: // byte string, text string
		raw, err := d.take(arg)
		if err != nil {
			return nil, err
		}
		if major == 2 {
			return raw, nil
		}
		return string(raw), nil
	case 4: // array
		n, err := d.count(arg)
		if err != nil {
			return nil, err
		}
		out := make([]any, 0, n)
		for i := 0; i < n; i++ {
			v, err := d.value(depth + 1)
			if err != nil {
				return nil, err
			}
			if _, isBreak := v.(cborBreak); isBreak {
				return nil, errCBORBreak
			}
			out = append(out, v)
		}
		return out, nil
	case 5: // map
		n, err := d.count(arg)
		if err != nil {
			return nil, err
		}
		out := make(map[any]any, n)
		for i := 0; i < n; i++ {
			k, err := d.value(depth + 1)
			if err != nil {
				return nil, err
			}
			v, err := d.value(depth + 1)
			if err != nil {
				return nil, err
			}
			if err := putKey(out, k, v); err != nil {
				return nil, err
			}
		}
		return out, nil
	case 6: // tag: the content is what matters here
		return d.value(depth + 1)
	}
	return nil, fmt.Errorf("cbor: major type %d", major)
}

// argument reads the additional information that follows the initial byte.
func (d *cborDecoder) argument(minor byte) (uint64, error) {
	switch {
	case minor < 24:
		return uint64(minor), nil
	case minor == 24:
		raw, err := d.take(1)
		if err != nil {
			return 0, err
		}
		return uint64(raw[0]), nil
	case minor == 25:
		raw, err := d.take(2)
		if err != nil {
			return 0, err
		}
		return uint64(binary.BigEndian.Uint16(raw)), nil
	case minor == 26:
		raw, err := d.take(4)
		if err != nil {
			return 0, err
		}
		return uint64(binary.BigEndian.Uint32(raw)), nil
	case minor == 27:
		raw, err := d.take(8)
		if err != nil {
			return 0, err
		}
		return binary.BigEndian.Uint64(raw), nil
	}
	return 0, fmt.Errorf("cbor: reserved additional information %d", minor)
}

func (d *cborDecoder) simple(minor byte) (any, error) {
	switch minor {
	case 20:
		return false, nil
	case 21:
		return true, nil
	case 22, 23: // null, undefined
		return nil, nil
	case 24: // one-byte simple value
		_, err := d.take(1)
		return nil, err
	case 25:
		raw, err := d.take(2)
		if err != nil {
			return nil, err
		}
		return float64(float16(binary.BigEndian.Uint16(raw))), nil
	case 26:
		raw, err := d.take(4)
		if err != nil {
			return nil, err
		}
		return float64(math.Float32frombits(binary.BigEndian.Uint32(raw))), nil
	case 27:
		raw, err := d.take(8)
		if err != nil {
			return nil, err
		}
		return math.Float64frombits(binary.BigEndian.Uint64(raw)), nil
	}
	return nil, nil // simple values 0-19: no meaning here
}

// indefinite reads the streaming form of a string, array or map: items follow
// until a break marker rather than a count being declared up front.
func (d *cborDecoder) indefinite(major byte, depth int) (any, error) {
	switch major {
	case 2, 3: // string, written as a run of definite-length chunks
		var out []byte
		for {
			v, err := d.value(depth + 1)
			if err != nil {
				return nil, err
			}
			if _, isBreak := v.(cborBreak); isBreak {
				if major == 2 {
					return out, nil
				}
				return string(out), nil
			}
			switch chunk := v.(type) {
			case []byte:
				out = append(out, chunk...)
			case string:
				out = append(out, chunk...)
			default:
				return nil, fmt.Errorf("cbor: indefinite string holds a %T", v)
			}
		}
	case 4: // array
		out := []any{}
		for {
			v, err := d.value(depth + 1)
			if err != nil {
				return nil, err
			}
			if _, isBreak := v.(cborBreak); isBreak {
				return out, nil
			}
			out = append(out, v)
		}
	case 5: // map
		out := map[any]any{}
		for {
			k, err := d.value(depth + 1)
			if err != nil {
				return nil, err
			}
			if _, isBreak := k.(cborBreak); isBreak {
				return out, nil
			}
			v, err := d.value(depth + 1)
			if err != nil {
				return nil, err
			}
			if _, isBreak := v.(cborBreak); isBreak {
				return nil, errCBORBreak
			}
			if err := putKey(out, k, v); err != nil {
				return nil, err
			}
		}
	}
	return nil, fmt.Errorf("cbor: major type %d has no indefinite form", major)
}

// putKey stores a decoded pair, refusing the key types Go cannot use as map keys.
// C2PA keys its maps by text and COSE by integer, so nothing legitimate is lost.
func putKey(m map[any]any, k, v any) error {
	switch k.(type) {
	case []byte, []any, map[any]any, cborBreak:
		return fmt.Errorf("cbor: map key of type %T", k)
	}
	m[k] = v
	return nil
}

// take returns n bytes, refusing a length the input cannot satisfy. Checking
// against the remaining input rather than allocating first is what keeps a
// declared length of four gigabytes from becoming a four gigabyte allocation.
func (d *cborDecoder) take(n uint64) ([]byte, error) {
	if n > uint64(len(d.buf)-d.at) {
		return nil, errCBORShort
	}
	out := d.buf[d.at : d.at+int(n)]
	d.at += int(n)
	return out, nil
}

// count converts a declared item count, refusing one larger than the input could
// possibly hold: every item costs at least one byte.
func (d *cborDecoder) count(arg uint64) (int, error) {
	if arg > uint64(len(d.buf)-d.at) {
		return 0, errCBORShort
	}
	return int(arg), nil
}

// float16 converts a half-precision float. Present for completeness of the
// decoder rather than because C2PA uses one.
func float16(bits uint16) float32 {
	sign := uint32(bits&0x8000) << 16
	exp := uint32(bits>>10) & 0x1f
	frac := uint32(bits & 0x03ff)
	switch exp {
	case 0:
		if frac == 0 {
			return math.Float32frombits(sign)
		}
		// Subnormal: shift until the implied bit appears, dropping the exponent
		// by one each time. A half's smallest normal exponent is 2^-14, which is
		// field value 113 once biased for single precision.
		exp32 := uint32(113)
		for frac&0x0400 == 0 {
			frac <<= 1
			exp32--
		}
		frac &= 0x03ff
		return math.Float32frombits(sign | exp32<<23 | frac<<13)
	case 0x1f:
		return math.Float32frombits(sign | 0xff<<23 | frac<<13)
	}
	return math.Float32frombits(sign | (exp+127-15)<<23 | frac<<13)
}

// The accessors below exist so the manifest reader can walk a decoded value
// without a type switch at every step. A missing or wrongly-typed field is not an
// error: manifests are written by many producers and augur reports what it can
// read rather than refusing a file over one unexpected field.

func cborMap(v any) map[any]any {
	m, _ := v.(map[any]any)
	return m
}

func cborArray(v any) []any {
	a, _ := v.([]any)
	return a
}

func cborGet(v any, key any) any {
	m, ok := v.(map[any]any)
	if !ok {
		return nil
	}
	return m[key]
}

func cborString(v any) string {
	s, _ := v.(string)
	return s
}

func cborBytes(v any) []byte {
	b, _ := v.([]byte)
	return b
}

func cborInt(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case uint64:
		if n <= math.MaxInt64 {
			return int64(n), true
		}
	}
	return 0, false
}
