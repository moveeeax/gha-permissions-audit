# gha-permissions-audit

[![ci](https://github.com/moveeeax/gha-permissions-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/gha-permissions-audit/actions/workflows/ci.yml)
[![go](https://img.shields.io/badge/go-1.26%2B-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Audit GitHub Actions workflows for `GITHUB_TOKEN` permission hygiene, and print the minimal
`permissions` block to paste.

Every workflow runs with a token. Most repositories never say which one, so the job gets whatever
the org default hands out — on older repositories that is read **and write** for every scope, handed
to every third-party action in the file. The fix is four lines of YAML, but nothing complains when
they are missing. The mirror problem is just as common: a workflow that genuinely needs
`id-token: write` for AWS OIDC sets `permissions: read-all` at the top and dies at the last step of
a release pipeline.

Existing workflow linters check syntax. This one reasons about what the steps actually do.

## What it checks

| Rule | Severity | What it catches |
| --- | --- | --- |
| `no-permissions` | warning | no `permissions` block at workflow or job level — the job inherits the repository default |
| `write-all` | error | `permissions: write-all` (and the blanket `write: all` map form) |
| `unused-write` | warning | a scope granted `write` that no step appears to use |
| `missing-id-token` | error | an OIDC action (`aws-actions/configure-aws-credentials`, `azure/login`, `google-github-actions/auth`, `pypa/gh-action-pypi-publish`) without `id-token: write` |
| `missing-contents-write` | error | a release step (`softprops/action-gh-release`, `actions/create-release`, `ncipollo/release-action`, `gh release create`) without `contents: write` |
| `pr-target-write` | error | `pull_request_target` with `contents: write` — the classic injection shape |

Every finding carries the file, job id, rule id, severity and a ready-to-paste `permissions` block
computed from the steps that job actually runs.

## Install

Requires Go 1.26 or newer.

```sh
go install github.com/moveeeax/gha-permissions-audit/cmd/gha-permissions-audit@latest
```

Or build from a checkout:

```sh
go build -o gha-permissions-audit ./cmd/gha-permissions-audit
```

## Usage

```sh
gha-permissions-audit --dir .github/workflows
gha-permissions-audit --format markdown --fail-on error
gha-permissions-audit --ignore unused-write --min-severity error
```

Real output, run against this repository's own fixtures:

```console
$ gha-permissions-audit --dir testdata/workflows
testdata/workflows/no-permissions.yml
  warning no-permissions          line 1
          no permissions block at workflow or job level; every job gets the repository default token, which on older repositories is write for every scope
          minimal block:
            permissions:
              contents: read

testdata/workflows/oidc-missing-id-token.yml
  error   missing-id-token        job deploy, line 9
          job "deploy" calls aws-actions/configure-aws-credentials but has no id-token: write; the OIDC token request will fail
          minimal block:
            permissions:
              contents: read
              id-token: write

testdata/workflows/release-missing-contents.yml
  error   missing-contents-write  job publish, line 9
          job "publish" runs softprops/action-gh-release but has no contents: write; the release step will fail
          minimal block:
            permissions:
              contents: write

8 finding(s): 4 error, 4 warning — 7 workflow(s), 8 job(s) audited
```

### Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `--dir PATH` | `.github/workflows` | workflow directory, or a single workflow file |
| `--format FORMAT` | `table` | `table`, `json` or `markdown` |
| `--min-severity LEVEL` | `warning` | lowest severity to report |
| `--fail-on LEVEL` | `error` | severity that makes the exit code 1; `never` to always exit 0 |
| `--ignore RULE` | — | suppress a rule, repeatable |
| `--config PATH` | `.github/permissions-audit.yml` if present | extra action and `run` mappings, see [Your own mappings](#your-own-mappings) |
| `--list-rules` | — | print the rule table |

Exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` a workflow or the config file could
not be parsed, or the flags were wrong. `--format json` emits `{findings: [...], summary: {...}}` for piping into
`jq`.

## In CI

The repository ships a composite action, so a repository can audit its own workflows:

```yaml
permissions:
  contents: read

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-go@v7
        with:
          go-version: "1.27.x"
      - uses: moveeeax/gha-permissions-audit@v0
        with:
          dir: .github/workflows
          format: markdown
          fail-on: error
```

With `format: markdown` the report is appended to the job summary. Action inputs: `dir`, `format`,
`min-severity`, `fail-on`, `ignore` (comma-separated), `config`, `summary`. It exposes a `findings` output
with the count.

`examples/least-privilege.yml` is a workflow this tool reports nothing for;
`examples/audit-own-workflows.yml` is the drop-in audit job.

## How it works

Workflows are parsed with `go.yaml.in/yaml/v3` as a node tree rather than unmarshalled into structs,
for two reasons. Findings need real line numbers, and the raw scalar text matters: YAML 1.1 resolves
a bare `on` key to a boolean, so a struct-based parse of `on:` loses the trigger map unless you
compare `Node.Value` instead of the resolved value.

For each job the effective permissions are resolved in GitHub's own order — job block, then workflow
block, then the implicit repository default (treated as unknown, which is why a missing block is a
finding rather than an assumption). A small static table maps known actions and shell patterns to
the scopes they require, and the minimal block is the union of those needs with `contents: read` as
the floor.

The table is deliberately small. A wrong entry is worse than a missing one, because every entry can
become an error-severity finding in somebody's CI.

## One caveat

`unused-write` is a heuristic, and an honest one: it only knows the actions and shell patterns in
the table. A job that writes to the repository through `curl` against the REST API, or through an
action nobody has mapped yet, will be reported as over-granted when it is not. That is why it is a
warning rather than an error. Map those steps in [your own config](#your-own-mappings), or drop the
rule with `--ignore unused-write`. The three error-severity rules
have no such ambiguity — they fire on shapes that either fail at runtime or hand a writable token to
untrusted code.

## Your own mappings

In-house actions and scripts are the main source of `unused-write` false positives. Describe them in
`.github/permissions-audit.yml` and the tool reads the file from the working directory (the
repository root, in CI) on every run; `--config PATH` points somewhere else.

```yaml
mappings:
  - action: my-org/deploy-action
    scopes:
      deployments: write
  - run: ./scripts/pr-comment.sh
    scopes:
      pull-requests: write
```

An `action` entry matches the `uses` value without its ref, so `my-org/deploy-action@v2` and
`@main` both match; writing a ref in the entry is an error. A `run` entry is literal text searched
for in each step's script, with a word boundary at each end that starts or ends with a letter, digit
or underscore. Scope names and levels are checked against the `GITHUB_TOKEN` scopes GitHub
documents, so a typo such as `pull-request: write` fails the run with exit code 2 instead of doing
nothing.

Mappings add to the built-in table. They raise the needs used by `unused-write` and by the
suggested block, but cannot lower a built-in entry, and they never make a step count as an OIDC or
release step for the error-severity rules.

## Development

```sh
go test ./...
gofmt -l .
go vet ./...
```

Fixtures live in `testdata/workflows/`: one clean workflow and one per rule. `testdata/config/`
holds a workflow with in-house steps and the mappings file that covers them. CI runs on
`ubuntu-latest` across Go 1.26 and 1.27, and the `self-audit` job runs the tool against this
repository's own workflows.

## License

MIT — see [LICENSE](LICENSE).
