package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const configFixtures = "../../testdata/config"

func loadMappings(t *testing.T) *Mappings {
	t.Helper()
	m, err := LoadConfig(filepath.Join(configFixtures, "permissions-audit.yml"))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	return m
}

func TestInHouseStepsAreUnusedWriteWithoutConfig(t *testing.T) {
	wf, err := ParseFile(filepath.Join(configFixtures, "in-house.yml"), "in-house.yml")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	got := Analyze([]*Workflow{wf}, Options{MinSeverity: SeverityWarning})
	if len(got) != 2 {
		t.Fatalf("expected deployments and pull-requests reported as unused, got %v", rules(got))
	}
	for _, f := range got {
		if f.Rule != RuleUnusedWrite {
			t.Fatalf("unexpected rule %s", f.Rule)
		}
	}
}

func TestConfigMappingsClearUnusedWrite(t *testing.T) {
	wf, err := ParseFile(filepath.Join(configFixtures, "in-house.yml"), "in-house.yml")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	m := loadMappings(t)
	if m.Len() != 2 {
		t.Fatalf("expected 2 mappings, got %d", m.Len())
	}
	got := Analyze([]*Workflow{wf}, Options{MinSeverity: SeverityWarning, Mappings: m})
	if len(got) != 0 {
		t.Fatalf("config should cover both writes, got %v", rules(got))
	}
	want := "permissions:\n  contents: read\n  deployments: write\n  pull-requests: write\n"
	if block := minimalBlock(wf.Jobs[0], m); block != want {
		t.Fatalf("minimal block = %q, want %q", block, want)
	}
}

func TestConfigAddsToBuiltInTable(t *testing.T) {
	m, err := ParseConfig([]byte("mappings:\n  - action: actions/labeler\n    scopes:\n      issues: write\n"))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	needs, _ := jobNeeds(Job{Steps: []Step{{Uses: "actions/labeler@v6"}}}, m)
	if needs["pull-requests"] != "write" || needs["issues"] != "write" {
		t.Fatalf("built-in and config needs should both apply, got %v", needs)
	}

	// A read entry cannot lower a built-in write.
	m, err = ParseConfig([]byte("mappings:\n  - action: actions/labeler\n    scopes:\n      pull-requests: read\n"))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	needs, _ = jobNeeds(Job{Steps: []Step{{Uses: "actions/labeler@v6"}}}, m)
	if needs["pull-requests"] != "write" {
		t.Fatalf("config must not lower a built-in need, got %v", needs)
	}
}

func TestConfigDoesNotFeedErrorRules(t *testing.T) {
	m, err := ParseConfig([]byte("mappings:\n  - action: example-org/cloud-login\n    scopes:\n      id-token: write\n"))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	wf := &Workflow{Rel: "w.yml", Perms: Permissions{Kind: PermMap, Scopes: map[string]string{"contents": "read"}}}
	wf.Jobs = []Job{{ID: "login", Line: 5, Steps: []Step{{Uses: "example-org/cloud-login@v1"}}}}
	got := Analyze([]*Workflow{wf}, Options{MinSeverity: SeverityWarning, Mappings: m})
	if len(got) != 0 {
		t.Fatalf("a config entry should not raise missing-id-token, got %v", rules(got))
	}
}

func TestConfigRunPatternIsLiteralWithWordBoundaries(t *testing.T) {
	m, err := ParseConfig([]byte("mappings:\n  - run: deploy.sh --prod\n    scopes:\n      deployments: write\n"))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	for run, want := range map[string]bool{
		"./deploy.sh --prod":            true,
		"bash deploy.sh --prod && echo": true,
		"deployXsh --prod":              false, // the dot is literal
		"deploy.sh --production":        false,
		"redeploy.sh --prod":            false,
	} {
		got := len(stepNeeds(Step{Run: run}, m)) == 1
		if got != want {
			t.Errorf("run %q matched = %v, want %v", run, got, want)
		}
	}
}

func TestConfigRejectsBadEntries(t *testing.T) {
	for name, src := range map[string]string{
		"unknown key":      "mappings:\n  - action: a/b\n    scope:\n      contents: write\n",
		"unknown top key":  "mapping:\n  - action: a/b\n",
		"neither":          "mappings:\n  - scopes:\n      contents: write\n",
		"both":             "mappings:\n  - action: a/b\n    run: x\n    scopes:\n      contents: write\n",
		"ref":              "mappings:\n  - action: a/b@v1\n    scopes:\n      contents: write\n",
		"no scopes":        "mappings:\n  - action: a/b\n",
		"unknown scope":    "mappings:\n  - action: a/b\n    scopes:\n      pull-request: write\n",
		"bad level":        "mappings:\n  - action: a/b\n    scopes:\n      contents: admin\n",
		"id-token read":    "mappings:\n  - action: a/b\n    scopes:\n      id-token: read\n",
		"none is not need": "mappings:\n  - action: a/b\n    scopes:\n      contents: none\n",
		"not yaml":         "mappings: [\n",
	} {
		if _, err := ParseConfig([]byte(src)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if m, err := ParseConfig(nil); err != nil || m.Len() != 0 {
		t.Fatalf("an empty file should load as no mappings, got %v, %v", m, err)
	}
}

func TestLoadConfigNamesTheFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "permissions-audit.yml")
	if err := os.WriteFile(p, []byte("mappings:\n  - action: a/b\n    scopes:\n      nope: write\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadConfig(p)
	if err == nil || !strings.Contains(err.Error(), p) || !strings.Contains(err.Error(), "mappings[0]") {
		t.Fatalf("error should name the file and entry, got %v", err)
	}
}

func TestFindConfig(t *testing.T) {
	root := t.TempDir()
	if got := FindConfig(root); got != "" {
		t.Fatalf("empty root: got %q", got)
	}
	if err := os.MkdirAll(filepath.Join(root, ".github"), 0o755); err != nil {
		t.Fatal(err)
	}
	yaml := filepath.Join(root, ".github", "permissions-audit.yaml")
	if err := os.WriteFile(yaml, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := FindConfig(root); got != yaml {
		t.Fatalf("got %q, want %q", got, yaml)
	}
	yml := filepath.Join(root, ".github", "permissions-audit.yml")
	if err := os.WriteFile(yml, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := FindConfig(root); got != yml {
		t.Fatalf(".yml should win over .yaml, got %q", got)
	}
}
