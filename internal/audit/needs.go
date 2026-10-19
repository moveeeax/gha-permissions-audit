package audit

import (
	"regexp"
	"sort"
	"strings"
)

// Need is one scope a step demands, with the evidence for it.
type Need struct {
	Scope  string
	Level  string
	Reason string
}

type actionRule struct {
	// action is the `uses` value without a ref, matched exactly.
	action string
	scopes map[string]string
	// oidc marks actions that exchange the workflow token for a cloud
	// credential; they are useless without id-token: write.
	oidc bool
	// release marks actions that create or edit a GitHub release.
	release bool
}

// actionTable maps known actions to the scopes they require. Kept deliberately
// small: a wrong entry is worse than a missing one, because every entry can
// turn into an error-severity finding.
var actionTable = []actionRule{
	{action: "aws-actions/configure-aws-credentials", scopes: map[string]string{"id-token": "write"}, oidc: true},
	{action: "azure/login", scopes: map[string]string{"id-token": "write"}, oidc: true},
	{action: "google-github-actions/auth", scopes: map[string]string{"id-token": "write"}, oidc: true},
	{action: "pypa/gh-action-pypi-publish", scopes: map[string]string{"id-token": "write"}, oidc: true},

	{action: "softprops/action-gh-release", scopes: map[string]string{"contents": "write"}, release: true},
	{action: "actions/create-release", scopes: map[string]string{"contents": "write"}, release: true},
	{action: "ncipollo/release-action", scopes: map[string]string{"contents": "write"}, release: true},

	{action: "peter-evans/create-pull-request", scopes: map[string]string{"contents": "write", "pull-requests": "write"}},
	{action: "peter-evans/create-or-update-comment", scopes: map[string]string{"issues": "write"}},
	{action: "actions/stale", scopes: map[string]string{"issues": "write", "pull-requests": "write"}},
	{action: "actions/labeler", scopes: map[string]string{"pull-requests": "write"}},

	{action: "github/codeql-action/analyze", scopes: map[string]string{"security-events": "write"}},
	{action: "github/codeql-action/upload-sarif", scopes: map[string]string{"security-events": "write"}},

	{action: "actions/deploy-pages", scopes: map[string]string{"pages": "write", "id-token": "write"}},
}

type runRule struct {
	re      *regexp.Regexp
	scopes  map[string]string
	what    string
	release bool
}

// runTable matches shell patterns whose required scope is unambiguous.
var runTable = []runRule{
	{re: regexp.MustCompile(`\bgh release (create|upload|edit|delete)\b`), scopes: map[string]string{"contents": "write"}, what: "gh release", release: true},
	{re: regexp.MustCompile(`\bgit push\b`), scopes: map[string]string{"contents": "write"}, what: "git push"},
	{re: regexp.MustCompile(`\bgh pr (comment|edit|merge|close|review)\b`), scopes: map[string]string{"pull-requests": "write"}, what: "gh pr"},
	{re: regexp.MustCompile(`\bgh issue (create|comment|edit|close)\b`), scopes: map[string]string{"issues": "write"}, what: "gh issue"},
	{re: regexp.MustCompile(`\bdocker push\s+ghcr\.io/`), scopes: map[string]string{"packages": "write"}, what: "docker push to ghcr.io"},
	{re: regexp.MustCompile(`\bnpm publish\b`), scopes: map[string]string{"packages": "write"}, what: "npm publish"},
}

// StepNeeds returns the scopes a single step requires.
func StepNeeds(s Step) []Need {
	var out []Need
	if a := s.Action(); a != "" {
		for _, r := range actionTable {
			if r.action != a {
				continue
			}
			for scope, level := range r.scopes {
				out = append(out, Need{Scope: scope, Level: level, Reason: a})
			}
		}
		// A ghcr.io login on its own proves nothing, but a login plus a
		// build-push-action in the same job does.
		if a == "docker/login-action" && strings.Contains(s.With["registry"], "ghcr.io") {
			out = append(out, Need{Scope: "packages", Level: "write", Reason: "docker/login-action against ghcr.io"})
		}
	}
	if s.Run != "" {
		for _, r := range runTable {
			if r.re.MatchString(s.Run) {
				for scope, level := range r.scopes {
					out = append(out, Need{Scope: scope, Level: level, Reason: r.what})
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Scope < out[j].Scope })
	return out
}

// JobNeeds folds every step's needs into one scope -> level map, write winning
// over read, plus the reason recorded for each scope.
func JobNeeds(j Job) (map[string]string, map[string]string) {
	levels := map[string]string{}
	reasons := map[string]string{}
	for _, s := range j.Steps {
		for _, n := range StepNeeds(s) {
			if levels[n.Scope] != "write" {
				levels[n.Scope] = n.Level
				reasons[n.Scope] = n.Reason
			}
		}
	}
	return levels, reasons
}

// oidcSteps returns the OIDC actions a job calls.
func oidcSteps(j Job) []string {
	var out []string
	for _, s := range j.Steps {
		a := s.Action()
		for _, r := range actionTable {
			if r.oidc && r.action == a {
				out = append(out, a)
			}
		}
	}
	return out
}

// releaseSteps returns the release/publish steps a job runs.
func releaseSteps(j Job) []string {
	var out []string
	for _, s := range j.Steps {
		a := s.Action()
		for _, r := range actionTable {
			if r.release && r.action == a {
				out = append(out, a)
			}
		}
		if s.Run != "" {
			for _, r := range runTable {
				if r.release && r.re.MatchString(s.Run) {
					out = append(out, r.what)
				}
			}
		}
	}
	return out
}

// MinimalBlock renders the least-privilege permissions block for a job:
// contents: read as the floor, plus every scope the steps actually need.
func MinimalBlock(j Job) string {
	scopes := map[string]string{"contents": "read"}
	needs, _ := JobNeeds(j)
	for scope, level := range needs {
		if level == "write" || scopes[scope] == "" {
			scopes[scope] = level
		}
	}
	return renderBlock(scopes)
}

func renderBlock(scopes map[string]string) string {
	keys := make([]string, 0, len(scopes))
	for k := range scopes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("permissions:\n")
	for _, k := range keys {
		b.WriteString("  " + k + ": " + scopes[k] + "\n")
	}
	return b.String()
}
