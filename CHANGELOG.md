# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased] - 0.2.0

### Changed

- Minimum Go version is now 1.26; CI tests Go 1.26 and 1.27.
- Switched the YAML parser from the archived `gopkg.in/yaml.v3` to its maintained
  successor `go.yaml.in/yaml/v3` v3.0.6.
- CI, README and examples use `actions/checkout@v7` and `actions/setup-go@v7`;
  the release example uses `softprops/action-gh-release@v3` and
  `aws-actions/configure-aws-credentials@v6`.

### Added

- Dependabot configuration for GitHub Actions and Go modules.
- This changelog.

## [0.1.0] - 2026-10-19

### Added

- First release: `gha-permissions-audit` CLI and composite action with the
  `no-permissions`, `write-all`, `unused-write`, `missing-id-token`,
  `missing-contents-write` and `pr-target-write` rules, table/json/markdown
  output and a suggested minimal `permissions` block per finding.

[Unreleased]: https://github.com/moveeeax/gha-permissions-audit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/moveeeax/gha-permissions-audit/releases/tag/v0.1.0
