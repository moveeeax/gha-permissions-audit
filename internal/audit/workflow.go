// Package audit parses GitHub Actions workflows and reports GITHUB_TOKEN
// permission problems.
package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// PermKind describes the shape of a permissions block.
type PermKind int

const (
	// PermAbsent means no permissions key was written at this level.
	PermAbsent PermKind = iota
	// PermWriteAll is `permissions: write-all`.
	PermWriteAll
	// PermReadAll is `permissions: read-all`.
	PermReadAll
	// PermMap is an explicit scope mapping, possibly empty (`permissions: {}`).
	PermMap
)

// Permissions is an effective or declared permissions block.
type Permissions struct {
	Kind   PermKind
	Scopes map[string]string
	Line   int
}

// Present reports whether the block was written at all.
func (p Permissions) Present() bool { return p.Kind != PermAbsent }

// Level returns the granted level for a scope: "read", "write" or "none".
// An absent block returns "" — the effective level is whatever the repository
// default hands out, which we cannot know from the file alone.
func (p Permissions) Level(scope string) string {
	switch p.Kind {
	case PermWriteAll:
		return "write"
	case PermReadAll:
		return "read"
	case PermMap:
		if v, ok := p.Scopes[scope]; ok {
			return v
		}
		return "none"
	}
	return ""
}

// Step is one entry of a job's steps list.
type Step struct {
	Name string
	Uses string
	Run  string
	With map[string]string
	Line int
}

// Action returns the `uses` value without its version ref.
func (s Step) Action() string {
	if s.Uses == "" {
		return ""
	}
	if i := strings.Index(s.Uses, "@"); i >= 0 {
		return s.Uses[:i]
	}
	return s.Uses
}

// Label names a step in a finding message.
func (s Step) Label() string {
	if s.Name != "" {
		return s.Name
	}
	if a := s.Action(); a != "" {
		return a
	}
	return "run step"
}

// Job is one entry of a workflow's jobs mapping.
type Job struct {
	ID    string
	Line  int
	Perms Permissions
	Steps []Step
}

// Workflow is a parsed workflow file.
type Workflow struct {
	Path     string
	Rel      string
	Name     string
	Triggers []string
	Perms    Permissions
	Jobs     []Job
}

// HasTrigger reports whether the workflow fires on the given event.
func (w *Workflow) HasTrigger(event string) bool {
	for _, t := range w.Triggers {
		if t == event {
			return true
		}
	}
	return false
}

// EffectivePerms resolves the permissions a job actually runs with: its own
// block if it has one, otherwise the workflow block, otherwise absent.
func (w *Workflow) EffectivePerms(j Job) Permissions {
	if j.Perms.Present() {
		return j.Perms
	}
	return w.Perms
}

func mapGet(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		// Compare the raw scalar text, not the resolved value. YAML 1.1 treats
		// `on` as a boolean, so a workflow's `on:` key arrives tagged !!bool
		// with Value still set to "on".
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

func parsePermissions(n *yaml.Node) Permissions {
	if n == nil {
		return Permissions{Kind: PermAbsent}
	}
	switch n.Kind {
	case yaml.ScalarNode:
		switch strings.TrimSpace(n.Value) {
		case "write-all":
			return Permissions{Kind: PermWriteAll, Line: n.Line}
		case "read-all":
			return Permissions{Kind: PermReadAll, Line: n.Line}
		}
		return Permissions{Kind: PermMap, Scopes: map[string]string{}, Line: n.Line}
	case yaml.MappingNode:
		scopes := map[string]string{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			scopes[n.Content[i].Value] = strings.TrimSpace(n.Content[i+1].Value)
		}
		// `permissions: {write: all}` is the blanket form some repositories use.
		if v, ok := scopes["write"]; ok && v == "all" && len(scopes) == 1 {
			return Permissions{Kind: PermWriteAll, Line: n.Line}
		}
		return Permissions{Kind: PermMap, Scopes: scopes, Line: n.Line}
	}
	return Permissions{Kind: PermAbsent}
}

func parseTriggers(n *yaml.Node) []string {
	if n == nil {
		return nil
	}
	switch n.Kind {
	case yaml.ScalarNode:
		if n.Value == "" {
			return nil
		}
		return []string{n.Value}
	case yaml.SequenceNode:
		var out []string
		for _, c := range n.Content {
			out = append(out, c.Value)
		}
		return out
	case yaml.MappingNode:
		var out []string
		for i := 0; i+1 < len(n.Content); i += 2 {
			out = append(out, n.Content[i].Value)
		}
		return out
	}
	return nil
}

func parseStep(n *yaml.Node) Step {
	s := Step{Line: n.Line}
	if n.Kind != yaml.MappingNode {
		return s
	}
	if v := mapGet(n, "name"); v != nil {
		s.Name = v.Value
	}
	if v := mapGet(n, "uses"); v != nil {
		s.Uses = strings.TrimSpace(v.Value)
	}
	if v := mapGet(n, "run"); v != nil {
		s.Run = v.Value
	}
	if v := mapGet(n, "with"); v != nil && v.Kind == yaml.MappingNode {
		s.With = map[string]string{}
		for i := 0; i+1 < len(v.Content); i += 2 {
			s.With[v.Content[i].Value] = strings.TrimSpace(v.Content[i+1].Value)
		}
	}
	return s
}

// ParseFile reads one workflow file. rel is the path used in findings.
func ParseFile(path, rel string) (*Workflow, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var root yaml.Node
	if err := yaml.Unmarshal(b, &root); err != nil {
		return nil, fmt.Errorf("%s: %w", rel, err)
	}
	if len(root.Content) == 0 {
		return nil, fmt.Errorf("%s: empty document", rel)
	}
	doc := root.Content[0]
	if doc.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s: top level is not a mapping", rel)
	}
	wf := &Workflow{Path: path, Rel: rel}
	if n := mapGet(doc, "name"); n != nil {
		wf.Name = n.Value
	}
	wf.Triggers = parseTriggers(mapGet(doc, "on"))
	wf.Perms = parsePermissions(mapGet(doc, "permissions"))

	jobs := mapGet(doc, "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s: no jobs mapping", rel)
	}
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		key, val := jobs.Content[i], jobs.Content[i+1]
		j := Job{ID: key.Value, Line: key.Line}
		if val.Kind == yaml.MappingNode {
			j.Perms = parsePermissions(mapGet(val, "permissions"))
			// Reusable-workflow jobs have `uses:` and no steps; that is fine,
			// they simply contribute no inferred needs.
			if st := mapGet(val, "steps"); st != nil && st.Kind == yaml.SequenceNode {
				for _, sn := range st.Content {
					j.Steps = append(j.Steps, parseStep(sn))
				}
			}
		}
		wf.Jobs = append(wf.Jobs, j)
	}
	return wf, nil
}

// Discover parses every .yml/.yaml file directly under dir.
func Discover(dir string) ([]*Workflow, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext == ".yml" || ext == ".yaml" {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	var out []*Workflow
	for _, n := range names {
		wf, err := ParseFile(filepath.Join(dir, n), filepath.Join(dir, n))
		if err != nil {
			return nil, err
		}
		out = append(out, wf)
	}
	return out, nil
}
