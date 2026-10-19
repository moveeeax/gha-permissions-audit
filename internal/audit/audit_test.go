package audit

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const fixtures = "../../testdata/workflows"

func load(t *testing.T, name string) *Workflow {
	t.Helper()
	p := filepath.Join(fixtures, name)
	wf, err := ParseFile(p, name)
	if err != nil {
		t.Fatalf("ParseFile(%s): %v", name, err)
	}
	return wf
}

func analyze(t *testing.T, name string, opt Options) []Finding {
	t.Helper()
	if opt.MinSeverity == "" {
		opt.MinSeverity = SeverityWarning
	}
	if opt.FailOn == "" {
		opt.FailOn = SeverityError
	}
	return Analyze([]*Workflow{load(t, name)}, opt)
}

func rules(findings []Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.Rule)
	}
	return out
}

func TestCleanWorkflowHasNoFindings(t *testing.T) {
	got := analyze(t, "clean.yml", Options{})
	if len(got) != 0 {
		t.Fatalf("expected no findings, got %v", rules(got))
	}
	if code := ExitCode(got, SeverityError); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
}

func TestNoPermissionsReportedOncePerWorkflow(t *testing.T) {
	wf := load(t, "no-permissions.yml")
	if len(wf.Jobs) != 2 {
		t.Fatalf("expected 2 jobs, got %d", len(wf.Jobs))
	}
	got := analyze(t, "no-permissions.yml", Options{})
	if len(got) != 1 {
		t.Fatalf("expected exactly one finding for two jobs, got %v", rules(got))
	}
	f := got[0]
	if f.Rule != RuleNoPermissions || f.Severity != SeverityWarning {
		t.Fatalf("got rule %s severity %s", f.Rule, f.Severity)
	}
	if f.Suggested != "permissions:\n  contents: read\n" {
		t.Fatalf("suggested block = %q", f.Suggested)
	}
}

func TestExplicitMinimalBlockIsNotFlagged(t *testing.T) {
	// The clean fixture already carries contents: read; make sure the
	// no-permissions rule does not fire when only a job declares a block.
	wf := load(t, "clean.yml")
	wf.Perms = Permissions{Kind: PermAbsent}
	wf.Jobs[0].Perms = Permissions{Kind: PermMap, Scopes: map[string]string{"contents": "read"}, Line: 7}
	got := Analyze([]*Workflow{wf}, Options{MinSeverity: SeverityWarning})
	if len(got) != 0 {
		t.Fatalf("job-level block should satisfy the rule, got %v", rules(got))
	}
}

func TestWriteAllIsError(t *testing.T) {
	got := analyze(t, "write-all.yml", Options{})
	if len(got) != 1 || got[0].Rule != RuleWriteAll {
		t.Fatalf("expected one write-all finding, got %v", rules(got))
	}
	if got[0].Severity != SeverityError {
		t.Fatalf("severity = %s, want error", got[0].Severity)
	}
	if got[0].Line != 6 {
		t.Fatalf("line = %d, want 6 (the permissions key)", got[0].Line)
	}
	if code := ExitCode(got, SeverityError); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

func TestBlanketWriteAllMapForm(t *testing.T) {
	if p := permsFromYAML(t, "permissions:\n  write: all\n"); p.Kind != PermWriteAll {
		t.Fatalf("`write: all` should resolve to write-all, got kind %d", p.Kind)
	}
	if p := permsFromYAML(t, "permissions: read-all\n"); p.Kind != PermReadAll {
		t.Fatalf("read-all should resolve to PermReadAll, got kind %d", p.Kind)
	}
	if p := permsFromYAML(t, "permissions: {}\n"); p.Kind != PermMap || len(p.Scopes) != 0 {
		t.Fatalf("empty map should stay an empty PermMap, got kind %d scopes %v", p.Kind, p.Scopes)
	}
	if p := permsFromYAML(t, "name: x\n"); p.Present() {
		t.Fatal("a missing key must be PermAbsent")
	}
}

func permsFromYAML(t *testing.T, src string) Permissions {
	t.Helper()
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(src), &root); err != nil {
		t.Fatalf("yaml.Unmarshal: %v", err)
	}
	return parsePermissions(mapGet(root.Content[0], "permissions"))
}

func TestOIDCMissingIDTokenSuggestsBothScopes(t *testing.T) {
	got := analyze(t, "oidc-missing-id-token.yml", Options{})
	if len(got) != 1 || got[0].Rule != RuleMissingIDToken {
		t.Fatalf("expected one missing-id-token finding, got %v", rules(got))
	}
	f := got[0]
	if f.Severity != SeverityError {
		t.Fatalf("severity = %s, want error", f.Severity)
	}
	if f.Job != "deploy" {
		t.Fatalf("job = %q, want deploy", f.Job)
	}
	if !strings.Contains(f.Message, "aws-actions/configure-aws-credentials") {
		t.Fatalf("message should name the action: %s", f.Message)
	}
	for _, want := range []string{"id-token: write", "contents: read"} {
		if !strings.Contains(f.Suggested, want) {
			t.Fatalf("suggested block %q missing %q", f.Suggested, want)
		}
	}
}

func TestOIDCWithIDTokenIsClean(t *testing.T) {
	wf := load(t, "oidc-missing-id-token.yml")
	wf.Perms.Scopes["id-token"] = "write"
	got := Analyze([]*Workflow{wf}, Options{MinSeverity: SeverityWarning})
	if len(got) != 0 {
		t.Fatalf("granting id-token: write should clear the finding, got %v", rules(got))
	}
}

func TestReleaseMissingContentsWrite(t *testing.T) {
	got := analyze(t, "release-missing-contents.yml", Options{})
	if len(got) != 1 || got[0].Rule != RuleMissingContentsWrt {
		t.Fatalf("expected one missing-contents-write finding, got %v", rules(got))
	}
	if !strings.Contains(got[0].Suggested, "contents: write") {
		t.Fatalf("suggested block should raise contents to write: %q", got[0].Suggested)
	}
}

func TestReleaseDetectedFromShellCommand(t *testing.T) {
	j := Job{ID: "ship", Steps: []Step{{Run: "gh release create v1.0.0 --notes-file notes.md"}}}
	if got := releaseSteps(j); len(got) != 1 {
		t.Fatalf("gh release create should be detected, got %v", got)
	}
	if !strings.Contains(MinimalBlock(j), "contents: write") {
		t.Fatalf("minimal block = %q", MinimalBlock(j))
	}
}

func TestUnusedWriteFindings(t *testing.T) {
	got := analyze(t, "unused-write.yml", Options{})
	if len(got) != 2 {
		t.Fatalf("expected two unused-write findings, got %v", rules(got))
	}
	var scopes []string
	for _, f := range got {
		if f.Rule != RuleUnusedWrite || f.Severity != SeverityWarning {
			t.Fatalf("unexpected finding %s/%s", f.Rule, f.Severity)
		}
		scopes = append(scopes, f.Message)
	}
	if !strings.Contains(scopes[0], "contents") || !strings.Contains(scopes[1], "packages") {
		t.Fatalf("findings should be scope-sorted, got %v", scopes)
	}
	if got[0].Suggested != "permissions:\n  contents: read\n" {
		t.Fatalf("suggested block = %q", got[0].Suggested)
	}
}

func TestPullRequestTargetWrite(t *testing.T) {
	wf := load(t, "pr-target-write.yml")
	// YAML 1.1 resolves a bare `on` key to a boolean; the parser must still
	// find the trigger map.
	if !wf.HasTrigger("pull_request_target") {
		t.Fatalf("triggers = %v, want pull_request_target", wf.Triggers)
	}
	got := Analyze([]*Workflow{wf}, Options{MinSeverity: SeverityWarning})
	var seen []string
	for _, f := range got {
		seen = append(seen, f.Rule)
	}
	if !contains(seen, RulePRTargetWrite) {
		t.Fatalf("expected pr-target-write, got %v", seen)
	}
	for _, f := range got {
		if f.Rule == RulePRTargetWrite && f.Severity != SeverityError {
			t.Fatalf("pr-target-write severity = %s, want error", f.Severity)
		}
	}
	// actions/labeler legitimately needs pull-requests: write, so only
	// contents should be reported as over-granted.
	if !contains(seen, RuleUnusedWrite) {
		t.Fatalf("expected the unused contents: write to be reported too, got %v", seen)
	}
	for _, f := range got {
		if f.Rule == RuleUnusedWrite && strings.Contains(f.Message, "pull-requests") {
			t.Fatalf("pull-requests: write is used by actions/labeler, should not be flagged")
		}
	}
}

func TestIgnoreSuppressesExactlyOneRule(t *testing.T) {
	all := analyze(t, "pr-target-write.yml", Options{})
	kept := analyze(t, "pr-target-write.yml", Options{Ignore: map[string]bool{RuleUnusedWrite: true}})
	if len(kept) >= len(all) {
		t.Fatalf("--ignore did not drop anything: %v vs %v", rules(all), rules(kept))
	}
	for _, f := range kept {
		if f.Rule == RuleUnusedWrite {
			t.Fatal("unused-write survived --ignore")
		}
	}
	if code := ExitCode(kept, SeverityError); code != 1 {
		t.Fatalf("remaining error finding should still exit 1, got %d", code)
	}

	// Ignoring the only rule in a fixture leaves nothing and exits 0.
	none := analyze(t, "unused-write.yml", Options{Ignore: map[string]bool{RuleUnusedWrite: true}})
	if len(none) != 0 {
		t.Fatalf("expected no findings, got %v", rules(none))
	}
	if code := ExitCode(none, SeverityError); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
}

func TestMinSeverityFiltersWarnings(t *testing.T) {
	warn := analyze(t, "no-permissions.yml", Options{MinSeverity: SeverityWarning})
	if len(warn) != 1 {
		t.Fatalf("expected 1 finding at warning, got %d", len(warn))
	}
	errs := analyze(t, "no-permissions.yml", Options{MinSeverity: SeverityError})
	if len(errs) != 0 {
		t.Fatalf("expected 0 findings at --min-severity error, got %v", rules(errs))
	}
}

func TestExitCodeFailOnWarningAndNever(t *testing.T) {
	got := analyze(t, "no-permissions.yml", Options{})
	if code := ExitCode(got, SeverityError); code != 0 {
		t.Fatalf("a warning must not fail --fail-on error, got %d", code)
	}
	if code := ExitCode(got, SeverityWarning); code != 1 {
		t.Fatalf("--fail-on warning should fail, got %d", code)
	}
	if code := ExitCode(got, "never"); code != 0 {
		t.Fatalf("--fail-on never should always exit 0, got %d", code)
	}
}

func TestJobLevelOverridesWorkflowLevel(t *testing.T) {
	wf := load(t, "oidc-missing-id-token.yml")
	wf.Jobs[0].Perms = Permissions{Kind: PermMap, Scopes: map[string]string{"id-token": "write", "contents": "read"}, Line: 10}
	eff := wf.EffectivePerms(wf.Jobs[0])
	if eff.Level("id-token") != "write" {
		t.Fatalf("job block should win over the workflow block, got %q", eff.Level("id-token"))
	}
	if len(Analyze([]*Workflow{wf}, Options{MinSeverity: SeverityWarning})) != 0 {
		t.Fatal("job-level id-token: write should clear the finding")
	}
}

func TestParseErrorIsReported(t *testing.T) {
	if _, err := ParseFile("../../testdata/broken/broken.yml", "broken.yml"); err == nil {
		t.Fatal("expected a parse error for the broken fixture")
	}
	if _, err := ParseFile("../../testdata/does-not-exist.yml", "missing.yml"); err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

func TestDiscoverFindsEveryFixture(t *testing.T) {
	wfs, err := Discover(fixtures)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(wfs) != 7 {
		var names []string
		for _, w := range wfs {
			names = append(names, w.Rel)
		}
		t.Fatalf("expected 7 fixtures, got %d: %v", len(wfs), names)
	}
	// Findings must be ordered by file then line.
	got := Analyze(wfs, Options{MinSeverity: SeverityWarning})
	if len(got) == 0 {
		t.Fatal("expected findings across the fixture set")
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].File > got[i].File {
			t.Fatalf("findings not sorted by file: %s before %s", got[i-1].File, got[i].File)
		}
	}
	errs, warns := Counts(got)
	if errs == 0 || warns == 0 {
		t.Fatalf("expected both severities across fixtures, got %d errors %d warnings", errs, warns)
	}
}

func TestMinimalBlockIsSortedAndFloored(t *testing.T) {
	j := Job{ID: "deploy", Steps: []Step{
		{Uses: "aws-actions/configure-aws-credentials@v4"},
		{Uses: "softprops/action-gh-release@v2"},
	}}
	want := "permissions:\n  contents: write\n  id-token: write\n"
	if got := MinimalBlock(j); got != want {
		t.Fatalf("MinimalBlock() = %q, want %q", got, want)
	}
	empty := MinimalBlock(Job{ID: "test", Steps: []Step{{Run: "go test ./..."}}})
	if empty != "permissions:\n  contents: read\n" {
		t.Fatalf("a plain test job should floor at contents: read, got %q", empty)
	}
}

func TestStepNeedsIgnoresUnknownActions(t *testing.T) {
	if n := StepNeeds(Step{Uses: "actions/checkout@v4"}); len(n) != 0 {
		t.Fatalf("checkout needs nothing beyond the floor, got %v", n)
	}
	if n := StepNeeds(Step{Run: "echo hello"}); len(n) != 0 {
		t.Fatalf("a plain echo needs nothing, got %v", n)
	}
	n := StepNeeds(Step{Uses: "docker/login-action@v3", With: map[string]string{"registry": "ghcr.io"}})
	if len(n) != 1 || n[0].Scope != "packages" {
		t.Fatalf("ghcr login should need packages: write, got %v", n)
	}
}

func TestReusableWorkflowJobHasNoSteps(t *testing.T) {
	wf := &Workflow{Rel: "r.yml", Perms: Permissions{Kind: PermMap, Scopes: map[string]string{"contents": "read"}}}
	wf.Jobs = []Job{{ID: "call", Line: 5}}
	if got := Analyze([]*Workflow{wf}, Options{MinSeverity: SeverityWarning}); len(got) != 0 {
		t.Fatalf("a job with no steps should produce nothing, got %v", rules(got))
	}
}

func TestJSONReportShape(t *testing.T) {
	wfs := []*Workflow{load(t, "write-all.yml")}
	got := Analyze(wfs, Options{MinSeverity: SeverityWarning})
	var buf bytes.Buffer
	if err := WriteJSON(&buf, wfs, got); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var r Report
	if err := json.Unmarshal(buf.Bytes(), &r); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if len(r.Findings) != 1 || r.Findings[0].Rule != RuleWriteAll {
		t.Fatalf("findings = %+v", r.Findings)
	}
	if r.Summary.Workflows != 1 || r.Summary.Jobs != 1 || r.Summary.Errors != 1 {
		t.Fatalf("summary = %+v", r.Summary)
	}
}

func TestJSONReportEmptyFindingsIsArray(t *testing.T) {
	wfs := []*Workflow{load(t, "clean.yml")}
	var buf bytes.Buffer
	if err := WriteJSON(&buf, wfs, nil); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	if !strings.Contains(buf.String(), `"findings": []`) {
		t.Fatalf("empty findings should marshal as [], got %s", buf.String())
	}
}

func TestTableAndMarkdownOutput(t *testing.T) {
	wfs := []*Workflow{load(t, "oidc-missing-id-token.yml")}
	got := Analyze(wfs, Options{MinSeverity: SeverityWarning})

	var table bytes.Buffer
	if err := WriteTable(&table, wfs, got); err != nil {
		t.Fatalf("WriteTable: %v", err)
	}
	for _, want := range []string{"missing-id-token", "job deploy", "minimal block:", "id-token: write"} {
		if !strings.Contains(table.String(), want) {
			t.Fatalf("table output missing %q:\n%s", want, table.String())
		}
	}

	var md bytes.Buffer
	if err := WriteMarkdown(&md, wfs, got); err != nil {
		t.Fatalf("WriteMarkdown: %v", err)
	}
	for _, want := range []string{"| Severity |", "`missing-id-token`", "```yaml", "### Suggested blocks"} {
		if !strings.Contains(md.String(), want) {
			t.Fatalf("markdown output missing %q:\n%s", want, md.String())
		}
	}
}

func TestCleanOutputSaysSo(t *testing.T) {
	wfs := []*Workflow{load(t, "clean.yml")}
	var table, md bytes.Buffer
	if err := WriteTable(&table, wfs, nil); err != nil {
		t.Fatalf("WriteTable: %v", err)
	}
	if !strings.Contains(table.String(), "no findings") {
		t.Fatalf("table output = %q", table.String())
	}
	if err := WriteMarkdown(&md, wfs, nil); err != nil {
		t.Fatalf("WriteMarkdown: %v", err)
	}
	if !strings.Contains(md.String(), "No findings") {
		t.Fatalf("markdown output = %q", md.String())
	}
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
