package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixtures = "../../testdata/workflows"

func cli(args ...string) (int, string, string) {
	var out, errBuf bytes.Buffer
	code := run(args, &out, &errBuf)
	return code, out.String(), errBuf.String()
}

func TestCleanDirExitsZero(t *testing.T) {
	code, out, _ := cli("--dir", fixtures+"/clean.yml")
	if code != 0 {
		t.Fatalf("exit = %d, want 0\n%s", code, out)
	}
	if !strings.Contains(out, "no findings") {
		t.Fatalf("output = %q", out)
	}
}

func TestFindingsExitOne(t *testing.T) {
	code, out, _ := cli("--dir", fixtures+"/write-all.yml")
	if code != 1 {
		t.Fatalf("exit = %d, want 1\n%s", code, out)
	}
	if !strings.Contains(out, "write-all") {
		t.Fatalf("output = %q", out)
	}
}

func TestWarningOnlyExitsZeroUnlessFailOnWarning(t *testing.T) {
	if code, _, _ := cli("--dir", fixtures+"/no-permissions.yml"); code != 0 {
		t.Fatalf("exit = %d, want 0 (warnings do not fail by default)", code)
	}
	if code, _, _ := cli("--dir", fixtures+"/no-permissions.yml", "--fail-on", "warning"); code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if code, _, _ := cli("--dir", fixtures, "--fail-on", "never"); code != 0 {
		t.Fatalf("exit = %d, want 0 with --fail-on never", code)
	}
}

func TestIgnoreChangesExitCode(t *testing.T) {
	code, _, _ := cli("--dir", fixtures+"/unused-write.yml", "--fail-on", "warning")
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	code, out, _ := cli("--dir", fixtures+"/unused-write.yml", "--fail-on", "warning", "--ignore", "unused-write")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 after --ignore\n%s", code, out)
	}
}

func TestRepeatableIgnoreAndEqualsForm(t *testing.T) {
	code, out, _ := cli("--dir="+fixtures, "--format=json",
		"--ignore=no-permissions", "--ignore=unused-write", "--fail-on=never")
	if code != 0 {
		t.Fatalf("exit = %d, want 0\n%s", code, out)
	}
	var r struct {
		Findings []struct{ Rule string } `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	for _, f := range r.Findings {
		if f.Rule == "no-permissions" || f.Rule == "unused-write" {
			t.Fatalf("rule %s should have been ignored", f.Rule)
		}
	}
	if len(r.Findings) == 0 {
		t.Fatal("expected the error-severity findings to remain")
	}
}

func TestParseErrorExitsTwo(t *testing.T) {
	code, _, errOut := cli("--dir", "../../testdata/broken")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if errOut == "" {
		t.Fatal("expected the parse error on stderr")
	}
}

func TestBadFlagsExitTwo(t *testing.T) {
	for _, args := range [][]string{
		{"--format", "xml"},
		{"--min-severity", "info"},
		{"--fail-on", "always"},
		{"--ignore", "no-such-rule"},
		{"--nope"},
		{"--dir"},
		{"--dir", "../../testdata/nowhere"},
	} {
		if code, _, _ := cli(args...); code != 2 {
			t.Fatalf("%v: exit = %d, want 2", args, code)
		}
	}
}

func TestHelpVersionAndRules(t *testing.T) {
	code, out, _ := cli("--help")
	if code != 0 || !strings.Contains(out, "--min-severity") {
		t.Fatalf("help: exit %d output %q", code, out)
	}
	code, out, _ = cli("--version")
	if code != 0 || strings.TrimSpace(out) != version {
		t.Fatalf("version: exit %d output %q", code, out)
	}
	code, out, _ = cli("--list-rules")
	if code != 0 || !strings.Contains(out, "missing-id-token") {
		t.Fatalf("list-rules: exit %d output %q", code, out)
	}
}

func TestMarkdownFormat(t *testing.T) {
	code, out, _ := cli("--dir", fixtures+"/oidc-missing-id-token.yml", "--format", "markdown")
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(out, "## GITHUB_TOKEN permission audit") || !strings.Contains(out, "```yaml") {
		t.Fatalf("markdown output = %q", out)
	}
}

const configFixtures = "../../testdata/config"

func TestConfigFlagClearsUnusedWrite(t *testing.T) {
	wf := configFixtures + "/in-house.yml"
	if code, out, _ := cli("--dir", wf, "--fail-on", "warning"); code != 1 || !strings.Contains(out, "unused-write") {
		t.Fatalf("without config: exit %d\n%s", code, out)
	}
	code, out, errOut := cli("--dir", wf, "--fail-on", "warning", "--config", configFixtures+"/permissions-audit.yml")
	if code != 0 {
		t.Fatalf("with config: exit %d\n%s%s", code, out, errOut)
	}
}

func TestConfigErrorsExitTwo(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.yml")
	if err := os.WriteFile(bad, []byte("mappings:\n  - action: a/b\n    scopes:\n      contents: admin\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"--dir", fixtures, "--config", bad},
		{"--dir", fixtures, "--config", configFixtures + "/missing.yml"},
		{"--dir", fixtures, "--config"},
	} {
		if code, _, errOut := cli(args...); code != 2 || errOut == "" {
			t.Fatalf("%v: exit = %d stderr %q, want 2 and a message", args, code, errOut)
		}
	}
}

func TestDefaultConfigIsReadFromWorkingDirectory(t *testing.T) {
	wf, err := filepath.Abs(configFixtures + "/in-house.yml")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := os.ReadFile(configFixtures + "/permissions-audit.yml")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	t.Chdir(root)
	if code, _, _ := cli("--dir", wf, "--fail-on", "warning"); code != 1 {
		t.Fatalf("no default config yet: exit %d, want 1", code)
	}
	if err := os.MkdirAll(".github", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(".github/permissions-audit.yml", cfg, 0o644); err != nil {
		t.Fatal(err)
	}
	if code, out, errOut := cli("--dir", wf, "--fail-on", "warning"); code != 0 {
		t.Fatalf("default config should be picked up: exit %d\n%s%s", code, out, errOut)
	}
}
