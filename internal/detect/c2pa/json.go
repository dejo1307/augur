package c2pa

import "encoding/json"

// Some assertions are JSON rather than CBOR — the schema.org ones, and whatever a
// producer chooses to write that way. They decode into the same shape the CBOR
// accessors read, so the rest of this package does not have to care which form an
// assertion arrived in.
func jsonDecode(payload []byte) any {
	var v any
	if err := json.Unmarshal(payload, &v); err != nil {
		return nil
	}
	return asCBORShape(v)
}

func asCBORShape(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[any]any, len(t))
		for k, val := range t {
			out[k] = asCBORShape(val)
		}
		return out
	case []any:
		for i, val := range t {
			t[i] = asCBORShape(val)
		}
		return t
	}
	return v
}
