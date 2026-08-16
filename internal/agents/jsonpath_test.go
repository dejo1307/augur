package agents

import (
	"strings"
	"testing"
)

// at finds the offset of needle in doc, so the tests read as "the finding is
// here" rather than as a list of magic numbers.
func at(t *testing.T, doc, needle string) int {
	t.Helper()
	i := strings.Index(doc, needle)
	if i < 0 {
		t.Fatalf("fixture does not contain %q", needle)
	}
	return i
}

const settings = `{
  "permissions": {
    "allow": ["Bash(git status)", "Bash(npm test)"],
    "deny": []
  },
  "hooks": {
    "Stop": [
      {"matcher": "*", "hooks": [{"type": "command", "command": "echo done"}]}
    ]
  },
  "model": "opus"
}`

func TestPathAtNamesNestedPositions(t *testing.T) {
	cases := []struct {
		needle string
		want   string
	}{
		{"echo done", "hooks.Stop[0].hooks[0].command"},
		{"Bash(npm test)", "permissions.allow[1]"},
		{"Bash(git status)", "permissions.allow[0]"},
		{"opus", "model"},
		{"*", "hooks.Stop[0].matcher"},
	}
	for _, tc := range cases {
		got := PathAt([]byte(settings), at(t, settings, tc.needle))
		if got != tc.want {
			t.Errorf("PathAt(offset of %q) = %q, want %q", tc.needle, got, tc.want)
		}
	}
}

// A hidden character in a KEY is a different bug from one in a value: the
// setting silently stops applying. The path says which it is.
func TestPathAtDistinguishesKeys(t *testing.T) {
	doc := `{"permissions": {"allow": ["x"]}}`
	got := PathAt([]byte(doc), at(t, doc, "allow"))
	if !strings.HasSuffix(got, "(key)") {
		t.Errorf("PathAt on a key = %q, want it marked as a key", got)
	}
}

func TestPathAtOnMalformedJSON(t *testing.T) {
	// An honest empty answer beats a guess: the report simply omits the location.
	if got := PathAt([]byte(`{"a": `), 3); got != "" {
		t.Errorf("PathAt on truncated JSON = %q, want \"\"", got)
	}
	if got := PathAt([]byte("not json at all"), 4); got != "" {
		t.Errorf("PathAt on non-JSON = %q, want \"\"", got)
	}
}

func TestPathAtOutOfRange(t *testing.T) {
	if got := PathAt([]byte(settings), len(settings)+500); got != "" {
		t.Errorf("PathAt past the end = %q, want \"\"", got)
	}
}

func TestPathAtHandlesDeepNesting(t *testing.T) {
	doc := `{"a": {"b": {"c": [[{"d": "target"}]]}}}`
	if got := PathAt([]byte(doc), at(t, doc, "target")); got != "a.b.c[0][0].d" {
		t.Errorf("PathAt = %q, want a.b.c[0][0].d", got)
	}
}

func TestIsJSON(t *testing.T) {
	if !IsJSON([]byte(settings)) {
		t.Error("a valid settings document was not recognised as JSON")
	}
	if IsJSON([]byte("# Markdown\n")) {
		t.Error("markdown was recognised as JSON")
	}
}

// Config sources must be marked as such, or the report will quote their
// surroundings — and these files hold auth tokens.
func TestConfigSourcesAreMarkedConfig(t *testing.T) {
	for _, a := range Catalog() {
		for _, s := range a.Sources {
			isConfigPath := strings.HasSuffix(s.Glob, ".json") ||
				strings.HasSuffix(s.Glob, ".toml")
			if isConfigPath && s.Kind != Config {
				t.Errorf("%s: %q looks like a config but is Kind %q", a.ID, s.Glob, s.Kind)
			}
			if s.Kind == "" {
				t.Errorf("%s: %q has no Kind", a.ID, s.Glob)
			}
		}
	}
}
