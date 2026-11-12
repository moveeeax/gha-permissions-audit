package audit

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// DefaultConfigPaths are the files read from the working directory when no
// --config is given, first match wins.
var DefaultConfigPaths = []string{".github/permissions-audit.yml", ".github/permissions-audit.yaml"}

// tokenScopes lists every GITHUB_TOKEN scope and the levels it accepts, as
// documented under `permissions` in the workflow syntax reference. "none" is
// left out: a mapping says what a step needs, and needing nothing is the
// default.
var tokenScopes = map[string][]string{
	"actions":              {"read", "write"},
	"artifact-metadata":    {"read", "write"},
	"attestations":         {"read", "write"},
	"checks":               {"read", "write"},
	"code-quality":         {"read", "write"},
	"contents":             {"read", "write"},
	"copilot-requests":     {"write"},
	"deployments":          {"read", "write"},
	"discussions":          {"read", "write"},
	"id-token":             {"write"},
	"issues":               {"read", "write"},
	"packages":             {"read", "write"},
	"pages":                {"read", "write"},
	"pull-requests":        {"read", "write"},
	"security-events":      {"read", "write"},
	"statuses":             {"read", "write"},
	"vulnerability-alerts": {"read"},
}

// Mappings are user-supplied action and shell-pattern entries that add to the
// built-in tables. They only add needs: an entry cannot lower or remove what
// the built-in table says an action requires, and it never makes a step count
// as an OIDC or release step for the error-severity rules.
type Mappings struct {
	// Source is the file the mappings came from, for messages.
	Source  string
	actions []actionRule
	runs    []runRule
}

type configFile struct {
	Mappings []configEntry `yaml:"mappings"`
}

type configEntry struct {
	Action string            `yaml:"action"`
	Run    string            `yaml:"run"`
	Scopes map[string]string `yaml:"scopes"`
}

// LoadConfig reads a mappings file. Unknown keys, unknown scopes and levels a
// scope does not accept are errors, so a typo cannot silently do nothing.
func LoadConfig(path string) (*Mappings, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	m, err := ParseConfig(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	m.Source = path
	return m, nil
}

// FindConfig returns the first of DefaultConfigPaths that exists under root,
// or "" when there is none.
func FindConfig(root string) string {
	for _, p := range DefaultConfigPaths {
		full := filepath.Join(root, filepath.FromSlash(p))
		if st, err := os.Stat(full); err == nil && !st.IsDir() {
			return full
		}
	}
	return ""
}

// ParseConfig decodes the YAML body of a mappings file.
func ParseConfig(b []byte) (*Mappings, error) {
	var cf configFile
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&cf); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	m := &Mappings{}
	for i, e := range cf.Mappings {
		where := fmt.Sprintf("mappings[%d]", i)
		e.Action = strings.TrimSpace(e.Action)
		e.Run = strings.TrimSpace(e.Run)
		switch {
		case e.Action == "" && e.Run == "":
			return nil, fmt.Errorf("%s: needs either action or run", where)
		case e.Action != "" && e.Run != "":
			return nil, fmt.Errorf("%s: set action or run, not both", where)
		case strings.Contains(e.Action, "@"):
			return nil, fmt.Errorf("%s: action %q must not carry a ref; it matches every version", where, e.Action)
		}
		if len(e.Scopes) == 0 {
			return nil, fmt.Errorf("%s: scopes is empty", where)
		}
		scopes := map[string]string{}
		for scope, level := range e.Scopes {
			level = strings.TrimSpace(level)
			allowed, ok := tokenScopes[scope]
			if !ok {
				return nil, fmt.Errorf("%s: unknown scope %q (known: %s)", where, scope, strings.Join(knownScopes(), ", "))
			}
			if !containsString(allowed, level) {
				return nil, fmt.Errorf("%s: scope %s accepts %s, got %q", where, scope, strings.Join(allowed, " or "), level)
			}
			scopes[scope] = level
		}
		if e.Action != "" {
			m.actions = append(m.actions, actionRule{action: e.Action, scopes: scopes})
			continue
		}
		m.runs = append(m.runs, runRule{re: runPattern(e.Run), scopes: scopes, what: e.Run})
	}
	return m, nil
}

// Len returns the number of entries loaded.
func (m *Mappings) Len() int {
	if m == nil {
		return 0
	}
	return len(m.actions) + len(m.runs)
}

// runPattern matches the literal text of a run entry anywhere in a step's
// script, with a word boundary at each end that starts or ends with a word
// character, so `gh pr comment` does not match `xgh pr commented`.
func runPattern(lit string) *regexp.Regexp {
	expr := regexp.QuoteMeta(lit)
	if isWordByte(lit[0]) {
		expr = `\b` + expr
	}
	if isWordByte(lit[len(lit)-1]) {
		expr += `\b`
	}
	return regexp.MustCompile(expr)
}

func isWordByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func knownScopes() []string {
	out := make([]string, 0, len(tokenScopes))
	for k := range tokenScopes {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func containsString(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
