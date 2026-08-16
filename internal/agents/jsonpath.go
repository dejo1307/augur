package agents

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// PathAt names the position of a byte offset inside a JSON document, as a
// dotted path such as `hooks.Stop[0].command` or `permissions.allow[17]`.
//
// This exists because "offset 1423 in settings.json" tells nobody anything. The
// question a reader has about a finding in a config file is which setting it is
// in — whether the invisible character sits in a hook command that runs on every
// session, or in a display name nobody executes.
//
// It is also the safe way to report these files. A config commonly holds auth
// tokens, so printing the surrounding text to show a finding in context would
// spray credentials into a report the user might paste somewhere. A path says
// exactly where without quoting anything.
//
// Returns "" when the document does not parse or the offset is not inside any
// token — an honest empty answer rather than a guess.
func PathAt(data []byte, offset int) string {
	// Validate the whole document before locating anything. Without this, a
	// truncated file still yields a path for every token before the break —
	// a confident-looking answer derived from a document that does not parse,
	// which is exactly the kind of plausible-but-wrong output this tool exists
	// to avoid producing.
	if !IsJSON(data) {
		return ""
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	// frame tracks one open object or array.
	type frame struct {
		array     bool
		index     int    // next array index
		key       string // current object key
		expectKey bool
	}
	var stack []frame

	// path renders the enclosing frames plus the current position.
	path := func() string {
		var b strings.Builder
		for _, f := range stack {
			if f.array {
				fmt.Fprintf(&b, "[%d]", f.index)
				continue
			}
			if f.key == "" {
				continue
			}
			if b.Len() > 0 {
				b.WriteByte('.')
			}
			b.WriteString(f.key)
		}
		return b.String()
	}

	prev := int64(0)
	for {
		tok, err := dec.Token()
		if err != nil {
			return ""
		}
		end := dec.InputOffset()
		hit := int64(offset) >= prev && int64(offset) < end

		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				stack = append(stack, frame{expectKey: true})
			case '[':
				stack = append(stack, frame{array: true})
			case '}', ']':
				if len(stack) > 0 {
					stack = stack[:len(stack)-1]
				}
				// A closing delimiter belongs to the container, so advance the
				// parent's array index the same way a value would.
				if n := len(stack); n > 0 && stack[n-1].array {
					stack[n-1].index++
				} else if n > 0 {
					stack[n-1].expectKey = true
				}
			}
			prev = end
			continue
		default:
			n := len(stack)
			if n == 0 {
				if hit {
					return ""
				}
				prev = end
				continue
			}
			top := &stack[n-1]

			if !top.array && top.expectKey {
				// This token is a key. A finding inside a KEY is worth naming as
				// such: a homoglyph in a key means the setting silently does not
				// apply, which is a different bug from one in its value.
				if s, ok := t.(string); ok {
					top.key = s
				}
				top.expectKey = false
				if hit {
					return path() + " (key)"
				}
				prev = end
				continue
			}

			if hit {
				p := path()
				if top.array {
					// path() already rendered the index for this frame.
					return p
				}
				return p
			}

			if top.array {
				top.index++
			} else {
				top.expectKey = true
			}
		}
		prev = end
	}
}

// IsJSON reports whether data parses as a JSON document.
func IsJSON(data []byte) bool {
	return json.Valid(bytes.TrimSpace(data))
}
