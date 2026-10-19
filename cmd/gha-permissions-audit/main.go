// Command gha-permissions-audit audits GitHub Actions workflows for
// GITHUB_TOKEN permission hygiene and prints the minimal permissions block.
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/moveeeax/gha-permissions-audit/internal/audit"
)

const version = "0.1.0"

const usage = `gha-permissions-audit — least-privilege GITHUB_TOKEN auditor

Usage:
  gha-permissions-audit [flags]

Flags:
  --dir PATH             workflow directory or a single workflow file
                         (default ".github/workflows")
  --format FORMAT        table | json | markdown (default "table")
  --min-severity LEVEL   warning | error (default "warning")
  --fail-on LEVEL        warning | error | never (default "error")
  --ignore RULE          suppress a rule, repeatable
  --list-rules           print the rule table and exit
  --version              print the version and exit
  -h, --help             print this help and exit

Exit codes:
  0  no findings at or above --fail-on
  1  findings at or above --fail-on
  2  a workflow could not be parsed, or the flags were wrong
`

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	dir := ".github/workflows"
	format := "table"
	minSeverity := audit.SeverityWarning
	failOn := audit.SeverityError
	var ignore stringList

	// Hand-rolled parsing so --ignore can repeat and `--flag=value` and
	// `--flag value` both work without pulling in a flag library.
	for i := 0; i < len(args); i++ {
		a := args[i]
		name, val, hasVal := a, "", false
		if eq := strings.Index(a, "="); eq > 0 && strings.HasPrefix(a, "-") {
			name, val, hasVal = a[:eq], a[eq+1:], true
		}
		next := func() (string, bool) {
			if hasVal {
				return val, true
			}
			if i+1 < len(args) {
				i++
				return args[i], true
			}
			return "", false
		}
		switch name {
		case "-h", "--help", "help":
			fmt.Fprint(stdout, usage)
			return 0
		case "--version":
			fmt.Fprintln(stdout, version)
			return 0
		case "--list-rules":
			for _, r := range audit.Rules {
				fmt.Fprintf(stdout, "%-23s %-8s %s\n", r.ID, r.Severity, r.Description)
			}
			return 0
		case "--dir":
			v, ok := next()
			if !ok {
				fmt.Fprintln(stderr, "--dir needs a value")
				return 2
			}
			dir = v
		case "--format":
			v, ok := next()
			if !ok {
				fmt.Fprintln(stderr, "--format needs a value")
				return 2
			}
			format = v
		case "--min-severity":
			v, ok := next()
			if !ok {
				fmt.Fprintln(stderr, "--min-severity needs a value")
				return 2
			}
			minSeverity = v
		case "--fail-on":
			v, ok := next()
			if !ok {
				fmt.Fprintln(stderr, "--fail-on needs a value")
				return 2
			}
			failOn = v
		case "--ignore":
			v, ok := next()
			if !ok {
				fmt.Fprintln(stderr, "--ignore needs a value")
				return 2
			}
			ignore.Set(v)
		default:
			fmt.Fprintf(stderr, "unknown flag %q\n\n%s", a, usage)
			return 2
		}
	}

	switch format {
	case "table", "json", "markdown":
	default:
		fmt.Fprintf(stderr, "--format must be table, json or markdown, got %q\n", format)
		return 2
	}
	switch minSeverity {
	case audit.SeverityWarning, audit.SeverityError:
	default:
		fmt.Fprintf(stderr, "--min-severity must be warning or error, got %q\n", minSeverity)
		return 2
	}
	switch failOn {
	case audit.SeverityWarning, audit.SeverityError, "never":
	default:
		fmt.Fprintf(stderr, "--fail-on must be warning, error or never, got %q\n", failOn)
		return 2
	}

	known := map[string]bool{}
	for _, r := range audit.Rules {
		known[r.ID] = true
	}
	ignoreSet := map[string]bool{}
	for _, r := range ignore {
		if !known[r] {
			fmt.Fprintf(stderr, "unknown rule %q; run --list-rules\n", r)
			return 2
		}
		ignoreSet[r] = true
	}

	wfs, err := loadWorkflows(dir)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if len(wfs) == 0 {
		fmt.Fprintf(stderr, "no workflow files found in %s\n", dir)
		return 2
	}

	findings := audit.Analyze(wfs, audit.Options{
		MinSeverity: minSeverity,
		Ignore:      ignoreSet,
		FailOn:      failOn,
	})

	switch format {
	case "json":
		err = audit.WriteJSON(stdout, wfs, findings)
	case "markdown":
		err = audit.WriteMarkdown(stdout, wfs, findings)
	default:
		err = audit.WriteTable(stdout, wfs, findings)
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	return audit.ExitCode(findings, failOn)
}

func loadWorkflows(path string) ([]*audit.Workflow, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.IsDir() {
		return audit.Discover(path)
	}
	wf, err := audit.ParseFile(path, filepath.ToSlash(path))
	if err != nil {
		return nil, err
	}
	return []*audit.Workflow{wf}, nil
}
