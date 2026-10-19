package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Report is the JSON shape written by --format json.
type Report struct {
	Findings []Finding `json:"findings"`
	Summary  Summary   `json:"summary"`
}

// Summary counts what was audited and what was found.
type Summary struct {
	Workflows int `json:"workflows"`
	Jobs      int `json:"jobs"`
	Errors    int `json:"errors"`
	Warnings  int `json:"warnings"`
}

// NewSummary builds the summary for a run.
func NewSummary(wfs []*Workflow, findings []Finding) Summary {
	jobs := 0
	for _, wf := range wfs {
		jobs += len(wf.Jobs)
	}
	errs, warns := Counts(findings)
	return Summary{Workflows: len(wfs), Jobs: jobs, Errors: errs, Warnings: warns}
}

// WriteTable prints findings grouped by file, with the suggested block indented
// under each one.
func WriteTable(w io.Writer, wfs []*Workflow, findings []Finding) error {
	s := NewSummary(wfs, findings)
	if len(findings) == 0 {
		_, err := fmt.Fprintf(w, "no findings — %d workflow(s), %d job(s) audited\n", s.Workflows, s.Jobs)
		return err
	}
	var b strings.Builder
	file := ""
	for _, f := range findings {
		if f.File != file {
			if file != "" {
				b.WriteString("\n")
			}
			file = f.File
			b.WriteString(file + "\n")
		}
		loc := fmt.Sprintf("line %d", f.Line)
		if f.Job != "" {
			loc = fmt.Sprintf("job %s, line %d", f.Job, f.Line)
		}
		b.WriteString(fmt.Sprintf("  %-7s %-23s %s\n", f.Severity, f.Rule, loc))
		b.WriteString("          " + f.Message + "\n")
		if f.Suggested != "" {
			b.WriteString("          minimal block:\n")
			for _, line := range strings.Split(strings.TrimRight(f.Suggested, "\n"), "\n") {
				b.WriteString("            " + line + "\n")
			}
		}
	}
	b.WriteString(fmt.Sprintf("\n%d finding(s): %d error, %d warning — %d workflow(s), %d job(s) audited\n",
		len(findings), s.Errors, s.Warnings, s.Workflows, s.Jobs))
	_, err := io.WriteString(w, b.String())
	return err
}

// WriteJSON prints the machine-readable report.
func WriteJSON(w io.Writer, wfs []*Workflow, findings []Finding) error {
	if findings == nil {
		findings = []Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(Report{Findings: findings, Summary: NewSummary(wfs, findings)})
}

// WriteMarkdown prints a table plus the suggested blocks, suitable for a step
// summary or a PR comment.
func WriteMarkdown(w io.Writer, wfs []*Workflow, findings []Finding) error {
	s := NewSummary(wfs, findings)
	var b strings.Builder
	b.WriteString("## GITHUB_TOKEN permission audit\n\n")
	if len(findings) == 0 {
		b.WriteString(fmt.Sprintf("No findings. Audited %d workflow(s) and %d job(s).\n", s.Workflows, s.Jobs))
		_, err := io.WriteString(w, b.String())
		return err
	}
	b.WriteString(fmt.Sprintf("%d finding(s): **%d error**, **%d warning** across %d workflow(s).\n\n",
		len(findings), s.Errors, s.Warnings, s.Workflows))
	b.WriteString("| Severity | Rule | File | Job | Line | Finding |\n")
	b.WriteString("| --- | --- | --- | --- | --- | --- |\n")
	for _, f := range findings {
		job := f.Job
		if job == "" {
			job = "—"
		}
		b.WriteString(fmt.Sprintf("| %s | `%s` | `%s` | `%s` | %d | %s |\n",
			f.Severity, f.Rule, f.File, job, f.Line, escapePipes(f.Message)))
	}
	b.WriteString("\n### Suggested blocks\n\n")
	seen := map[string]bool{}
	for _, f := range findings {
		if f.Suggested == "" {
			continue
		}
		key := f.File + "\x00" + f.Job + "\x00" + f.Suggested
		if seen[key] {
			continue
		}
		seen[key] = true
		where := f.File
		if f.Job != "" {
			where += " — job `" + f.Job + "`"
		}
		b.WriteString(where + "\n\n```yaml\n" + strings.TrimRight(f.Suggested, "\n") + "\n```\n\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func escapePipes(s string) string { return strings.ReplaceAll(s, "|", `\|`) }
