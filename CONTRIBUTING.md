# Contributing to zitadel-cli

Thank you for your interest in contributing!

## Prerequisites

Only [Bazelisk](https://github.com/bazelbuild/bazelisk) is required. All other tools (golangci-lint, gofumpt) are managed by Bazel automatically.

```bash
# macOS
brew install bazelisk

# Linux/other
go install github.com/bazelbuild/bazelisk@latest
```

## Development Workflow

```bash
# Clone and build
git clone https://github.com/YOUR_USERNAME/zitadel-cli.git
cd zitadel-cli
make build

# Run tests
make test

# Format and lint before committing
make fmt
make lint

# Run all checks (format, lint, test)
make ci

# After adding/removing Go files
make gazelle
```

## Pull Request Checklist

1. `make ci` passes
2. Tests added/updated if needed
3. Documentation updated if needed
4. Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)

## Commit Message Format

```
<type>(<scope>): <description>

feat(project): add label support
fix(config): handle missing token file
docs: update installation guide
refactor(client): simplify error handling
```

**Types:** `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `build`, `ci`

## Project Structure

```
cmd/zitadel-cli/    Main entry point
internal/
  client/           Zitadel API client
  commands/         CLI commands
  config/           Configuration
  output/           Output formatting
  version/          Version info
```

## Questions?

Open an issue for discussion.
