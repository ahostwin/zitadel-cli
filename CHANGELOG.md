# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2024-12-30

### Added

- Multi-context support for managing multiple Zitadel instances
- Organization management commands (`org list`, `org get`)
- Project management commands (`project list`, `project get`, `project create`,
  `project delete`)
- Application management commands (`app list`, `app get`, `app create-oidc`,
  `app delete`)
- Human user management commands (`user list`, `user get`, `user create`,
  `user delete`, `user set-password`)
- Machine user management commands (`machine list`, `machine get`,
  `machine create`, `machine delete`)
- Personal Access Token commands (`pat list`, `pat create`, `pat delete`)
- Role management commands (`role list`, `role add`, `role remove`, `role grant`)
- Provisioning command for automated project setup with applications, roles,
  and users
- Health check command (`healthz`)
- Current context info command (`whoami`)
- Flexible output formats: table, JSON, YAML, name-only, and Go templates
- Configuration via file (`~/.zitadel/config.yaml`), environment variables,
  and CLI flags
- Token management via direct value, file reference, or environment variable
- Non-interactive mode with `--yes` flag for automation
- Homebrew tap installation support
- Cross-platform binary releases via Bazel

### Security

- Configuration files created with restricted permissions (0600/0700)
- Support for token files with proper filesystem permissions as alternative to
  plaintext token storage in config

[Unreleased]: https://github.com/roylee17/zitadel-cli/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/roylee17/zitadel-cli/releases/tag/v0.1.0
