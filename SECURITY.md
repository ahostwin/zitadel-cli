# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability, please report it privately by emailing
the maintainer directly. You can find contact information in the repository or
reach out via GitHub's private vulnerability reporting feature.

When reporting, please include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes (optional)

You can expect:

- Acknowledgment within 48 hours
- Regular updates on the status
- Credit in the security advisory (unless you prefer anonymity)

## Security Considerations

### Token Storage

This CLI stores authentication tokens in configuration files. Be aware of the
following security implications:

#### Plaintext Token Storage

Tokens stored directly in `~/.zitadel/config.yaml` are saved in plaintext:

```yaml
contexts:
  production:
    url: https://zitadel.example.com
    token: eyJhbGc...  # Stored in plaintext!
```

**Risks:**

- Anyone with read access to the config file can extract tokens
- Tokens may be exposed in backups or synced directories
- Accidental commits to version control

#### Recommended: Use Token Files

For better security, use the `token-file` option with restricted permissions:

```yaml
contexts:
  production:
    url: https://zitadel.example.com
    token-file: ~/.zitadel/tokens/production
```

Set up the token file with proper permissions:

```bash
# Create tokens directory with restricted access
mkdir -p ~/.zitadel/tokens
chmod 700 ~/.zitadel/tokens

# Store token in file with restricted permissions
echo "your-token-here" > ~/.zitadel/tokens/production
chmod 600 ~/.zitadel/tokens/production
```

#### Environment Variables

Using `ZITADEL_PAT` environment variable avoids storing tokens in files but
tokens may still appear in:

- Shell history (if set inline)
- Process listings
- Environment dumps in logs

### Configuration File Permissions

The CLI creates configuration files with restricted permissions (0600 for files,
0700 for directories), but you should verify:

```bash
# Check permissions
ls -la ~/.zitadel/

# Fix if needed
chmod 700 ~/.zitadel
chmod 600 ~/.zitadel/config.yaml
```

### TLS Verification

The `--insecure` flag disables TLS certificate verification. This should only
be used for development or testing, never in production. Disabling TLS
verification exposes you to man-in-the-middle attacks.

### Best Practices

1. **Rotate tokens regularly** - Use short-lived tokens when possible
2. **Use token files** - With proper filesystem permissions (600)
3. **Avoid inline tokens** - Don't use `--token` flag in scripts; use files or
   environment variables
4. **Restrict config access** - Ensure only your user can read `~/.zitadel/`
5. **Never commit tokens** - Add `~/.zitadel/` to global gitignore
6. **Audit access** - Regularly review who has access to machines with stored
   tokens

## Responsible Disclosure

We follow responsible disclosure practices. After a vulnerability is reported
and fixed, we will:

1. Release a patched version
2. Publish a security advisory
3. Credit the reporter (with permission)

We ask that you:

1. Give us reasonable time to address the issue before public disclosure
2. Avoid accessing or modifying data that doesn't belong to you
3. Act in good faith to avoid privacy violations and service disruption
