package audit

import (
	"fmt"
	"sort"
	"strings"
)

// Severities, ordered.
const (
	SeverityWarning = "warning"
	SeverityError   = "error"
)

var severityRank = map[string]int{SeverityWarning: 1, SeverityError: 2}

// Rule identifiers, all usable with --ignore.
const (
	RuleNoPermissions      = "no-permissions"
	RuleWriteAll           = "write-all"
	RuleUnusedWrite        = "unused-write"
	RuleMissingIDToken     = "missing-id-token"
	RuleMissingContentsWrt = "missing-contents-write"
	RulePRTargetWrite      = "pr-target-write"
)

// Rules lists every rule with a one-line description, for --list-rules.
var Rules = []struct {
	ID, Severity, Description string
}{
	{RuleNoPermissions, SeverityWarning, "no permissions block anywhere; the job inherits the repository default"},
	{RuleWriteAll, SeverityError, "permissions: write-all grants every scope to every step"},
	{RuleUnusedWrite, SeverityWarning, "a scope is granted write but no step appears to use it"},
	{RuleMissingIDToken, SeverityError, "an OIDC action runs without id-token: write"},
	{RuleMissingContentsWrt, SeverityError, "a release or publish step runs without contents: write"},
	{RulePRTargetWrite, SeverityError, "pull_request_target with contents: write runs untrusted code with a writable token"},
}

// Finding is one reported problem.
type Finding struct {
	File      string `json:"file"`
	Line      int    `json:"line"`
	Job       string `json:"job,omitempty"`
	Rule      string `json:"rule"`
	Severity  string `json:"severity"`
	Message   string `json:"message"`
	Suggested string `json:"suggested,omitempty"`
}

// Options control which findings survive to the report.
type Options struct {
	MinSeverity string
	Ignore      map[string]bool
	FailOn      string
}

// Analyze runs every rule over the parsed workflows and returns the findings
// that pass the ignore and min-severity filters, sorted by file and line.
func Analyze(wfs []*Workflow, opt Options) []Finding {
	var out []Finding
	add := func(f Finding) {
		if opt.Ignore[f.Rule] {
			return
		}
		if severityRank[f.Severity] < severityRank[opt.MinSeverity] {
			return
		}
		out = append(out, f)
	}

	for _, wf := range wfs {
		anyPerms := wf.Perms.Present()
		for _, j := range wf.Jobs {
			if j.Perms.Present() {
				anyPerms = true
			}
		}
		if !anyPerms {
			add(Finding{
				File:     wf.Rel,
				Line:     1,
				Rule:     RuleNoPermissions,
				Severity: SeverityWarning,
				Message: "no permissions block at workflow or job level; every job gets the repository " +
					"default token, which on older repositories is write for every scope",
				Suggested: renderBlock(map[string]string{"contents": "read"}),
			})
		}
		if wf.Perms.Kind == PermWriteAll {
			add(Finding{
				File:      wf.Rel,
				Line:      wf.Perms.Line,
				Rule:      RuleWriteAll,
				Severity:  SeverityError,
				Message:   "workflow-level permissions: write-all grants every scope to every job",
				Suggested: renderBlock(map[string]string{"contents": "read"}),
			})
		}

		for _, j := range wf.Jobs {
			eff := wf.EffectivePerms(j)
			needs, reasons := JobNeeds(j)
			block := MinimalBlock(j)

			if j.Perms.Kind == PermWriteAll {
				add(Finding{
					File:      wf.Rel,
					Line:      j.Perms.Line,
					Job:       j.ID,
					Rule:      RuleWriteAll,
					Severity:  SeverityError,
					Message:   fmt.Sprintf("job %q sets permissions: write-all", j.ID),
					Suggested: block,
				})
			}

			if oidc := oidcSteps(j); len(oidc) > 0 && eff.Level("id-token") != "write" {
				add(Finding{
					File:     wf.Rel,
					Line:     j.Line,
					Job:      j.ID,
					Rule:     RuleMissingIDToken,
					Severity: SeverityError,
					Message: fmt.Sprintf("job %q calls %s but has no id-token: write; the OIDC token request will fail",
						j.ID, strings.Join(dedupe(oidc), ", ")),
					Suggested: block,
				})
			}

			if rel := releaseSteps(j); len(rel) > 0 && eff.Level("contents") != "write" {
				add(Finding{
					File:     wf.Rel,
					Line:     j.Line,
					Job:      j.ID,
					Rule:     RuleMissingContentsWrt,
					Severity: SeverityError,
					Message: fmt.Sprintf("job %q runs %s but has no contents: write; the release step will fail",
						j.ID, strings.Join(dedupe(rel), ", ")),
					Suggested: block,
				})
			}

			// Only an explicit mapping can over-grant a single scope; write-all
			// is already reported by its own rule.
			if eff.Kind == PermMap {
				var over []string
				for scope, level := range eff.Scopes {
					if level == "write" && needs[scope] != "write" {
						over = append(over, scope)
					}
				}
				sort.Strings(over)
				for _, scope := range over {
					msg := fmt.Sprintf("job %q is granted %s: write but no step appears to use it", j.ID, scope)
					if r := reasons[scope]; r != "" {
						msg += fmt.Sprintf(" for writing (only %s needs it, at read level)", r)
					}
					add(Finding{
						File:      wf.Rel,
						Line:      eff.Line,
						Job:       j.ID,
						Rule:      RuleUnusedWrite,
						Severity:  SeverityWarning,
						Message:   msg,
						Suggested: block,
					})
				}
			}

			if wf.HasTrigger("pull_request_target") && eff.Level("contents") == "write" {
				add(Finding{
					File:     wf.Rel,
					Line:     j.Line,
					Job:      j.ID,
					Rule:     RulePRTargetWrite,
					Severity: SeverityError,
					Message: fmt.Sprintf("job %q runs on pull_request_target with contents: write; "+
						"a fork's code would execute with a token that can push", j.ID),
					Suggested: block,
				})
			}
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		if out[i].Line != out[j].Line {
			return out[i].Line < out[j].Line
		}
		return out[i].Rule < out[j].Rule
	})
	return out
}

// ExitCode maps findings to the process exit code honouring --fail-on.
func ExitCode(findings []Finding, failOn string) int {
	if failOn == "never" {
		return 0
	}
	threshold, ok := severityRank[failOn]
	if !ok {
		threshold = severityRank[SeverityError]
	}
	for _, f := range findings {
		if severityRank[f.Severity] >= threshold {
			return 1
		}
	}
	return 0
}

// Counts returns the number of findings per severity.
func Counts(findings []Finding) (errors, warnings int) {
	for _, f := range findings {
		switch f.Severity {
		case SeverityError:
			errors++
		case SeverityWarning:
			warnings++
		}
	}
	return
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
