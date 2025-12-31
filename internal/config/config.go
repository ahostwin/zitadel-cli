// Package config provides configuration management with multi-context support.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config represents the CLI configuration file.
type Config struct {
	// CurrentContext is the name of the active context.
	CurrentContext string `yaml:"current-context"`

	// Contexts is a map of named contexts.
	Contexts map[string]*Context `yaml:"contexts"`
}

// Context represents a Zitadel instance configuration.
type Context struct {
	// URL is the Zitadel instance URL.
	URL string `yaml:"url"`

	// Token is the Personal Access Token (optional, can use token file).
	Token string `yaml:"token,omitempty"`

	// TokenFile is the path to a file containing the token.
	TokenFile string `yaml:"token-file,omitempty"`

	// Insecure skips TLS verification.
	Insecure bool `yaml:"insecure,omitempty"`

	// Organization is the default organization ID for this context.
	Organization string `yaml:"organization,omitempty"`

	// Project is the default project name for this context.
	Project string `yaml:"project,omitempty"`
}

// DefaultConfigDir returns the default config directory path.
func DefaultConfigDir() string {
	if dir := os.Getenv("ZITADEL_CONFIG_DIR"); dir != "" {
		return dir
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".zitadel"
	}
	return filepath.Join(home, ".zitadel")
}

// DefaultConfigPath returns the default config file path.
func DefaultConfigPath() string {
	return filepath.Join(DefaultConfigDir(), "config.yaml")
}

// Load reads the configuration from the default path.
func Load() (*Config, error) {
	return LoadFrom(DefaultConfigPath())
}

// LoadFrom reads the configuration from the specified path.
func LoadFrom(path string) (*Config, error) {
	cfg := &Config{
		Contexts: make(map[string]*Context),
	}

	data, err := os.ReadFile(path) //nolint:gosec // Path comes from trusted sources (CLI flag or default config path)
	if err != nil {
		if os.IsNotExist(err) {
			// Return empty config if file doesn't exist
			return cfg, nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	return cfg, nil
}

// Save writes the configuration to the default path.
func (c *Config) Save() error {
	return c.SaveTo(DefaultConfigPath())
}

// SaveTo writes the configuration to the specified path.
func (c *Config) SaveTo(path string) error {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	return nil
}

// CurrentCtx returns the current context or nil if not set.
func (c *Config) CurrentCtx() *Context {
	if c.CurrentContext == "" {
		return nil
	}
	return c.Contexts[c.CurrentContext]
}

// SetContext adds or updates a context.
func (c *Config) SetContext(name string, ctx *Context) {
	if c.Contexts == nil {
		c.Contexts = make(map[string]*Context)
	}
	c.Contexts[name] = ctx
}

// DeleteContext removes a context.
func (c *Config) DeleteContext(name string) error {
	if _, ok := c.Contexts[name]; !ok {
		return fmt.Errorf("context '%s' not found", name)
	}
	delete(c.Contexts, name)
	if c.CurrentContext == name {
		c.CurrentContext = ""
	}
	return nil
}

// GetToken returns the token for the current context.
// It checks the context's Token field first, then TokenFile.
func (c *Config) GetToken() (string, error) {
	ctx := c.CurrentCtx()
	if ctx == nil {
		return "", fmt.Errorf("no current context set")
	}
	return ctx.GetToken()
}

// GetToken returns the token for this context.
func (ctx *Context) GetToken() (string, error) {
	// Direct token takes precedence
	if ctx.Token != "" {
		return ctx.Token, nil
	}

	// Try token file
	if ctx.TokenFile != "" {
		data, err := os.ReadFile(ctx.TokenFile)
		if err != nil {
			return "", fmt.Errorf("read token file: %w", err)
		}
		return string(data), nil
	}

	// Check environment variable
	if token := os.Getenv("ZITADEL_PAT"); token != "" {
		return token, nil
	}

	return "", fmt.Errorf("no token configured (set token, token-file, or ZITADEL_PAT)")
}

// Merge merges environment variables and CLI flags into the context.
func (ctx *Context) Merge(url, token string, insecure bool) {
	if url != "" {
		ctx.URL = url
	}
	if token != "" {
		ctx.Token = token
	}
	if insecure {
		ctx.Insecure = insecure
	}
}

// Validate checks that the context has required fields.
func (ctx *Context) Validate() error {
	if ctx.URL == "" {
		return fmt.Errorf("URL is required")
	}
	return nil
}
