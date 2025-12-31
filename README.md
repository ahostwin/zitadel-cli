# zitadel-cli

 comprehensive command-line tool for managing [Zitadel](https://zitadel.com/) identity and access management.

## Features

- **Multi-context support**: Manage multiple Zitadel instances with named contexts
- **Flexible output**: Table, JSON, YAML, and Go template formats
- **Complete resource management**: Organizations, projects, applications, users, roles
- **Automation-friendly**: Non-interactive mode, exit codes, machine-readable output
- **Secure**: Token management via files, environment variables, or secure prompts

## Installation

### Homebrew (macOS/Linux)

```bash
brew install roylee17/tap/zitadel-cli
```

### Go Install

```bash
go install github.com/roylee17/zitadel-cli/cmd/zitadel-cli@latest
```

### Binary Download

Download pre-built binaries from the [releases page](https://github.com/roylee17/zitadel-cli/releases).

### Build from Source

The only requirement is [Bazelisk](https://github.com/bazelbuild/bazelisk) (a Bazel version manager):

```bash
# Install Bazelisk
brew install bazelisk          # macOS
go install github.com/bazelbuild/bazelisk@latest  # or via Go

# Clone and build
git clone https://github.com/roylee17/zitadel-cli.git
cd zitadel-cli
bazel build //:zitadel-cli

# Run the binary
./bazel-bin/cmd/zitadel-cli/zitadel-cli version
```

## Quick Start

### 1. Configure a context

```bash
# Set up your first context
zitadel-cli context set production \
  --url https://your-zitadel-instance.com \
  --token YOUR_PAT_TOKEN

# Or use environment variables
export ZITADEL_URL=https://your-zitadel-instance.com
export ZITADEL_PAT=your-token
```

### 2. Verify connection

```bash
zitadel-cli healthz
zitadel-cli whoami
```

### 3. Manage resources

```bash
# List organizations
zitadel-cli org list

# List projects
zitadel-cli project list

# Create a project
zitadel-cli project create myproject
```

## Commands

| Command | Description |
|---------|-------------|
| `context` | Manage Zitadel contexts (multiple instances) |
| `org` | Manage organizations |
| `project` | Manage projects |
| `app` | Manage OIDC/API applications |
| `user` | Manage human users |
| `machine` | Manage machine users (service accounts) |
| `pat` | Manage Personal Access Tokens |
| `role` | Manage project roles and grants |
| `provision` | Provision complete project with apps |
| `healthz` | Check Zitadel health |
| `whoami` | Show current context information |

## Context Management

Contexts allow you to manage multiple Zitadel instances:

```bash
# List contexts
zitadel-cli context list

# Add a context
zitadel-cli context set staging --url https://staging.example.com

# Switch contexts
zitadel-cli context use production

# Use a specific context for one command
zitadel-cli --context staging project list
```

## Output Formats

```bash
# Table (default)
zitadel-cli project list

# JSON
zitadel-cli project list -o json

# YAML
zitadel-cli project list -o yaml

# Names only
zitadel-cli project list -o name

# Go template
zitadel-cli project list -o go-template='{{.id}}: {{.name}}'
```

## Provisioning

Provision a complete project with OIDC applications:

```bash
zitadel-cli provision myproject \
  --frontend-url https://app.example.com \
  --backend-url https://api.example.com \
  --create-roles \
  --create-admin \
  --admin-email admin@example.com \
  --admin-password SecurePassword123!
```

This creates:
- A project with the specified name
- A frontend SPA application (PKCE)
- A backend web application (client credentials)
- Standard roles (admin, user, viewer)
- An admin user with the admin role

## Configuration

Configuration is stored in `~/.zitadel/config.yaml`:

```yaml
current-context: production
contexts:
  production:
    url: https://zitadel.example.com
    token-file: ~/.zitadel/tokens/production
    organization: my-org
    project: my-project
  staging:
    url: https://staging.zitadel.example.com
    token: eyJhbGc...
    insecure: true
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `ZITADEL_URL` | Zitadel instance URL |
| `ZITADEL_PAT` | Personal Access Token |
| `ZITADEL_CONFIG_DIR` | Config directory (default: `~/.zitadel`) |
| `NO_COLOR` | Disable colored output |

### Priority

Configuration values are resolved in this order (highest to lowest):

1. Command-line flags
2. Environment variables
3. Context configuration
4. Defaults

## Shell Completion

Enable shell completion for tab-completion of commands, flags, and arguments.

### Bash

```bash
# Load completions for current session
source <(zitadel-cli completion bash)

# Load completions for every session (Linux)
zitadel-cli completion bash > /etc/bash_completion.d/zitadel-cli

# Load completions for every session (macOS with Homebrew)
zitadel-cli completion bash > $(brew --prefix)/etc/bash_completion.d/zitadel-cli
```

### Zsh

```bash
# Load completions for current session
source <(zitadel-cli completion zsh)

# Load completions for every session
zitadel-cli completion zsh > "${fpath[1]}/_zitadel-cli"
```

### Fish

```bash
# Load completions for current session
zitadel-cli completion fish | source

# Load completions for every session
zitadel-cli completion fish > ~/.config/fish/completions/zitadel-cli.fish
```

### PowerShell

```powershell
# Load completions for current session
zitadel-cli completion powershell | Out-String | Invoke-Expression

# Load completions for every session
zitadel-cli completion powershell > zitadel-cli.ps1
# Then source this file from your PowerShell profile
```

## Automation

### Non-interactive Mode

Use `--yes` to skip confirmation prompts:

```bash
zitadel-cli project delete myproject --yes
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error |

### Scripting Examples

```bash
# Get project ID
PROJECT_ID=$(zitadel-cli project get myproject -o json | jq -r '.id')

# List all projects as JSON
zitadel-cli project list -o json | jq '.[] | .name'

# Check if project exists
if zitadel-cli project get myproject >/dev/null 2>&1; then
  echo "Project exists"
fi
```

## Development

### Prerequisites

Only [Bazelisk](https://github.com/bazelbuild/bazelisk) is required. All other tools (golangci-lint, gofumpt) are managed by Bazel automatically.

```bash
# macOS
brew install bazelisk

# Or via Go
go install github.com/bazelbuild/bazelisk@latest
```

### Commands

```bash
make build    # Build CLI binary
make test     # Run tests
make lint     # Run linter (via Bazel)
make fmt      # Format code (via Bazel)
make ci       # Run all checks (fmt, lint, test)
make gazelle  # Update BUILD files after Go changes
make clean    # Clean build artifacts
```

### Direct Bazel Commands

```bash
bazel build //:zitadel-cli              # Build CLI
bazel build //:release-all              # Build all platforms
bazel test //...                        # Run tests
bazel run //:gazelle                    # Update BUILD files
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License - see [LICENSE](LICENSE) for details.
