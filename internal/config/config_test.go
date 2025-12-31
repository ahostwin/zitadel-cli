package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad_MissingFile(t *testing.T) {
	// Load from a non-existent path should return empty config
	cfg, err := LoadFrom("/nonexistent/path/config.yaml")
	require.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Empty(t, cfg.CurrentContext)
	assert.Empty(t, cfg.Contexts)
}

func TestLoad_ValidYAML(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	yamlContent := `current-context: production
contexts:
  production:
    url: https://zitadel.example.com
    token: prod-token-123
    insecure: false
    organization: org-123
    project: my-project
  development:
    url: https://localhost:8080
    token-file: /path/to/token
    insecure: true
`
	err := os.WriteFile(configPath, []byte(yamlContent), 0o600)
	require.NoError(t, err)

	cfg, err := LoadFrom(configPath)
	require.NoError(t, err)

	assert.Equal(t, "production", cfg.CurrentContext)
	assert.Len(t, cfg.Contexts, 2)

	// Check production context
	prodCtx := cfg.Contexts["production"]
	require.NotNil(t, prodCtx)
	assert.Equal(t, "https://zitadel.example.com", prodCtx.URL)
	assert.Equal(t, "prod-token-123", prodCtx.Token)
	assert.False(t, prodCtx.Insecure)
	assert.Equal(t, "org-123", prodCtx.Organization)
	assert.Equal(t, "my-project", prodCtx.Project)

	// Check development context
	devCtx := cfg.Contexts["development"]
	require.NotNil(t, devCtx)
	assert.Equal(t, "https://localhost:8080", devCtx.URL)
	assert.Equal(t, "/path/to/token", devCtx.TokenFile)
	assert.True(t, devCtx.Insecure)
}

func TestSave(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	cfg := &Config{
		CurrentContext: "test",
		Contexts: map[string]*Context{
			"test": {
				URL:      "https://test.example.com",
				Token:    "test-token",
				Insecure: true,
			},
		},
	}

	err := cfg.SaveTo(configPath)
	require.NoError(t, err)

	// Verify file exists and has correct permissions
	info, err := os.Stat(configPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	// Reload and verify
	loadedCfg, err := LoadFrom(configPath)
	require.NoError(t, err)
	assert.Equal(t, "test", loadedCfg.CurrentContext)
	assert.Len(t, loadedCfg.Contexts, 1)
	assert.Equal(t, "https://test.example.com", loadedCfg.Contexts["test"].URL)
	assert.Equal(t, "test-token", loadedCfg.Contexts["test"].Token)
	assert.True(t, loadedCfg.Contexts["test"].Insecure)
}

func TestSaveTo_CreatesDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	nestedPath := filepath.Join(tmpDir, "nested", "dir", "config.yaml")

	cfg := &Config{
		CurrentContext: "test",
		Contexts:       map[string]*Context{},
	}

	err := cfg.SaveTo(nestedPath)
	require.NoError(t, err)

	// Verify file was created
	_, err = os.Stat(nestedPath)
	require.NoError(t, err)
}

func TestCurrentCtx(t *testing.T) {
	tests := []struct {
		name        string
		cfg         *Config
		expectedNil bool
		expectedURL string
	}{
		{
			name: "returns nil when no current context set",
			cfg: &Config{
				CurrentContext: "",
				Contexts: map[string]*Context{
					"test": {URL: "https://test.example.com"},
				},
			},
			expectedNil: true,
		},
		{
			name: "returns nil when current context not found",
			cfg: &Config{
				CurrentContext: "nonexistent",
				Contexts: map[string]*Context{
					"test": {URL: "https://test.example.com"},
				},
			},
			expectedNil: true,
		},
		{
			name: "returns context when found",
			cfg: &Config{
				CurrentContext: "test",
				Contexts: map[string]*Context{
					"test": {URL: "https://test.example.com"},
				},
			},
			expectedNil: false,
			expectedURL: "https://test.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.cfg.CurrentCtx()
			if tt.expectedNil {
				assert.Nil(t, ctx)
			} else {
				require.NotNil(t, ctx)
				assert.Equal(t, tt.expectedURL, ctx.URL)
			}
		})
	}
}

func TestContext_GetToken_DirectToken(t *testing.T) {
	ctx := &Context{
		URL:   "https://example.com",
		Token: "direct-token-123",
	}

	token, err := ctx.GetToken()
	require.NoError(t, err)
	assert.Equal(t, "direct-token-123", token)
}

func TestContext_GetToken_TokenFile(t *testing.T) {
	tmpDir := t.TempDir()
	tokenFile := filepath.Join(tmpDir, "token")
	err := os.WriteFile(tokenFile, []byte("file-token-456"), 0o600)
	require.NoError(t, err)

	ctx := &Context{
		URL:       "https://example.com",
		TokenFile: tokenFile,
	}

	token, err := ctx.GetToken()
	require.NoError(t, err)
	assert.Equal(t, "file-token-456", token)
}

func TestContext_GetToken_TokenFileMissing(t *testing.T) {
	ctx := &Context{
		URL:       "https://example.com",
		TokenFile: "/nonexistent/token/file",
	}

	_, err := ctx.GetToken()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "read token file")
}

func TestContext_GetToken_EnvVar(t *testing.T) {
	// Save original env value and restore after test
	originalEnv := os.Getenv("ZITADEL_PAT")
	defer func() { _ = os.Setenv("ZITADEL_PAT", originalEnv) }()

	_ = os.Setenv("ZITADEL_PAT", "env-token-789")

	ctx := &Context{
		URL: "https://example.com",
		// No Token or TokenFile set
	}

	token, err := ctx.GetToken()
	require.NoError(t, err)
	assert.Equal(t, "env-token-789", token)
}

func TestContext_GetToken_Priority(t *testing.T) {
	// Direct token should take precedence over token file and env var
	tmpDir := t.TempDir()
	tokenFile := filepath.Join(tmpDir, "token")
	err := os.WriteFile(tokenFile, []byte("file-token"), 0o600)
	require.NoError(t, err)

	originalEnv := os.Getenv("ZITADEL_PAT")
	defer func() { _ = os.Setenv("ZITADEL_PAT", originalEnv) }()
	_ = os.Setenv("ZITADEL_PAT", "env-token")

	ctx := &Context{
		URL:       "https://example.com",
		Token:     "direct-token",
		TokenFile: tokenFile,
	}

	token, err := ctx.GetToken()
	require.NoError(t, err)
	assert.Equal(t, "direct-token", token)
}

func TestContext_GetToken_NoToken(t *testing.T) {
	// Clear env var
	originalEnv := os.Getenv("ZITADEL_PAT")
	defer func() { _ = os.Setenv("ZITADEL_PAT", originalEnv) }()
	_ = os.Unsetenv("ZITADEL_PAT")

	ctx := &Context{
		URL: "https://example.com",
	}

	_, err := ctx.GetToken()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no token configured")
}

func TestContext_Validate(t *testing.T) {
	tests := []struct {
		name        string
		ctx         *Context
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid context with URL",
			ctx:         &Context{URL: "https://example.com"},
			expectError: false,
		},
		{
			name:        "invalid context without URL",
			ctx:         &Context{Token: "some-token"},
			expectError: true,
			errorMsg:    "URL is required",
		},
		{
			name:        "invalid empty context",
			ctx:         &Context{},
			expectError: true,
			errorMsg:    "URL is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.ctx.Validate()
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestConfig_SetContext(t *testing.T) {
	cfg := &Config{}

	ctx := &Context{
		URL:   "https://example.com",
		Token: "test-token",
	}

	cfg.SetContext("test", ctx)

	assert.NotNil(t, cfg.Contexts)
	assert.Len(t, cfg.Contexts, 1)
	assert.Equal(t, ctx, cfg.Contexts["test"])
}

func TestConfig_DeleteContext(t *testing.T) {
	cfg := &Config{
		CurrentContext: "production",
		Contexts: map[string]*Context{
			"production":  {URL: "https://prod.example.com"},
			"development": {URL: "https://dev.example.com"},
		},
	}

	// Delete a non-current context
	err := cfg.DeleteContext("development")
	require.NoError(t, err)
	assert.Len(t, cfg.Contexts, 1)
	assert.Equal(t, "production", cfg.CurrentContext)

	// Delete the current context
	err = cfg.DeleteContext("production")
	require.NoError(t, err)
	assert.Empty(t, cfg.Contexts)
	assert.Empty(t, cfg.CurrentContext)

	// Try to delete non-existent context
	err = cfg.DeleteContext("nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestConfig_GetToken(t *testing.T) {
	t.Run("returns error when no current context", func(t *testing.T) {
		cfg := &Config{}
		_, err := cfg.GetToken()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no current context")
	})

	t.Run("returns token from current context", func(t *testing.T) {
		cfg := &Config{
			CurrentContext: "test",
			Contexts: map[string]*Context{
				"test": {
					URL:   "https://example.com",
					Token: "context-token",
				},
			},
		}
		token, err := cfg.GetToken()
		require.NoError(t, err)
		assert.Equal(t, "context-token", token)
	})
}

func TestContext_Merge(t *testing.T) {
	ctx := &Context{
		URL:      "https://original.com",
		Token:    "original-token",
		Insecure: false,
	}

	// Merge with new values
	ctx.Merge("https://new.com", "new-token", true)

	assert.Equal(t, "https://new.com", ctx.URL)
	assert.Equal(t, "new-token", ctx.Token)
	assert.True(t, ctx.Insecure)
}

func TestContext_Merge_EmptyValues(t *testing.T) {
	ctx := &Context{
		URL:      "https://original.com",
		Token:    "original-token",
		Insecure: true,
	}

	// Merge with empty values should preserve original
	ctx.Merge("", "", false)

	assert.Equal(t, "https://original.com", ctx.URL)
	assert.Equal(t, "original-token", ctx.Token)
	// Insecure is only set if true
	assert.True(t, ctx.Insecure)
}

func TestDefaultConfigDir(t *testing.T) {
	t.Run("uses ZITADEL_CONFIG_DIR if set", func(t *testing.T) {
		originalEnv := os.Getenv("ZITADEL_CONFIG_DIR")
		defer func() { _ = os.Setenv("ZITADEL_CONFIG_DIR", originalEnv) }()

		_ = os.Setenv("ZITADEL_CONFIG_DIR", "/custom/config/dir")
		assert.Equal(t, "/custom/config/dir", DefaultConfigDir())
	})

	t.Run("uses home directory if env not set", func(t *testing.T) {
		originalEnv := os.Getenv("ZITADEL_CONFIG_DIR")
		defer func() { _ = os.Setenv("ZITADEL_CONFIG_DIR", originalEnv) }()

		_ = os.Unsetenv("ZITADEL_CONFIG_DIR")
		dir := DefaultConfigDir()
		home, _ := os.UserHomeDir()
		assert.Equal(t, filepath.Join(home, ".zitadel"), dir)
	})
}
