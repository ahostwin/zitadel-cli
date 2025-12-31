// Package commands provides CLI command implementations.
package commands

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/roylee17/zitadel-cli/internal/config"
	"github.com/roylee17/zitadel-cli/internal/output"
)

var contextCmd = &cobra.Command{
	Use:     "context",
	Aliases: []string{"ctx"},
	Short:   "Manage Zitadel contexts",
	Long: `Manage multiple Zitadel instance configurations.

Contexts allow you to switch between different Zitadel instances easily.
Each context stores a URL, authentication token, and optional defaults.

Examples:
  # List all contexts
  zitadel-cli context list

  # Add a new context
  zitadel-cli context set production --url https://zitadel.example.com --token <PAT>

  # Switch to a context
  zitadel-cli context use production

  # Show current context
  zitadel-cli context current`,
}

var contextListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List all contexts",
	RunE: func(_ *cobra.Command, _ []string) error {
		if len(cfg.Contexts) == 0 {
			printer.Info("No contexts configured. Use 'zitadel-cli context set <name>' to add one.")
			return nil
		}

		var rows [][]string
		for name, ctx := range cfg.Contexts {
			current := ""
			if name == cfg.CurrentContext {
				current = "*"
			}
			rows = append(rows, []string{current, name, ctx.URL, ctx.Organization})
		}

		return printer.PrintTableRows([]string{"", "NAME", "URL", "ORGANIZATION"}, rows)
	},
}

var contextCurrentCmd = &cobra.Command{
	Use:   "current",
	Short: "Show current context",
	RunE: func(_ *cobra.Command, _ []string) error {
		if cfg.CurrentContext == "" {
			printer.Info("No context is currently set. Use 'zitadel-cli context use <name>' to set one.")
			return nil
		}

		ctx := cfg.CurrentCtx()
		if ctx == nil {
			return fmt.Errorf("current context '%s' not found in configuration", cfg.CurrentContext)
		}

		printer.PrintKeyValue(map[string]string{
			"Name":         cfg.CurrentContext,
			"URL":          ctx.URL,
			"Organization": ctx.Organization,
			"Project":      ctx.Project,
			"Insecure":     fmt.Sprintf("%t", ctx.Insecure),
		})
		return nil
	},
}

var contextUseCmd = &cobra.Command{
	Use:   "use <context-name>",
	Short: "Switch to a context",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		name := args[0]

		if _, exists := cfg.Contexts[name]; !exists {
			return fmt.Errorf("context '%s' not found", name)
		}

		cfg.CurrentContext = name
		if err := cfg.Save(); err != nil {
			return fmt.Errorf("save config: %w", err)
		}

		printer.Success("Switched to context '%s'", name)
		return nil
	},
}

var (
	ctxSetURL      string
	ctxSetToken    string
	ctxSetInsecure bool
	ctxSetOrg      string
	ctxSetProject  string
)

var contextSetCmd = &cobra.Command{
	Use:   "set <context-name>",
	Short: "Create or update a context",
	Long: `Create or update a context configuration.

Examples:
  # Create a new context with interactive token prompt
  zitadel-cli context set production --url https://zitadel.example.com

  # Create with all options
  zitadel-cli context set production \
    --url https://zitadel.example.com \
    --token <PAT> \
    --organization myorg \
    --project myproject

  # Update existing context
  zitadel-cli context set production --organization neworg`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		// Get existing context or create new one
		ctx := cfg.Contexts[name]
		if ctx == nil {
			ctx = &config.Context{}
			if cfg.Contexts == nil {
				cfg.Contexts = make(map[string]*config.Context)
			}
		}

		// Update fields if provided
		if ctxSetURL != "" {
			ctx.URL = ctxSetURL
		}
		if ctxSetToken != "" {
			ctx.Token = ctxSetToken
		}
		if cmd.Flags().Changed("insecure") {
			ctx.Insecure = ctxSetInsecure
		}
		if ctxSetOrg != "" {
			ctx.Organization = ctxSetOrg
		}
		if ctxSetProject != "" {
			ctx.Project = ctxSetProject
		}

		// Prompt for token if not provided and URL is set
		if ctx.Token == "" && ctx.TokenFile == "" && ctx.URL != "" {
			if token := os.Getenv("ZITADEL_PAT"); token != "" {
				ctx.Token = token
				printer.Info("Using token from ZITADEL_PAT environment variable")
			} else {
				token, err := output.PromptPassword("Personal Access Token (PAT)")
				if err != nil {
					return fmt.Errorf("prompt for token: %w", err)
				}
				ctx.Token = token
			}
		}

		cfg.Contexts[name] = ctx

		// Set as current if no current context
		if cfg.CurrentContext == "" {
			cfg.CurrentContext = name
		}

		if err := cfg.Save(); err != nil {
			return fmt.Errorf("save config: %w", err)
		}

		printer.Success("Context '%s' saved", name)
		return nil
	},
}

var contextDeleteCmd = &cobra.Command{
	Use:     "delete <context-name>",
	Aliases: []string{"rm"},
	Short:   "Delete a context",
	Args:    cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		name := args[0]

		if _, exists := cfg.Contexts[name]; !exists {
			return fmt.Errorf("context '%s' not found", name)
		}

		if !confirmAction(fmt.Sprintf("Delete context '%s'?", name)) {
			printer.Info("Cancelled")
			return nil
		}

		delete(cfg.Contexts, name)

		// Clear current context if it was deleted
		if cfg.CurrentContext == name {
			cfg.CurrentContext = ""
			// Set first available as current
			for n := range cfg.Contexts {
				cfg.CurrentContext = n
				break
			}
		}

		if err := cfg.Save(); err != nil {
			return fmt.Errorf("save config: %w", err)
		}

		printer.Success("Context '%s' deleted", name)
		return nil
	},
}

var contextRenameCmd = &cobra.Command{
	Use:   "rename <old-name> <new-name>",
	Short: "Rename a context",
	Args:  cobra.ExactArgs(2),
	RunE: func(_ *cobra.Command, args []string) error {
		oldName := args[0]
		newName := args[1]

		ctx, exists := cfg.Contexts[oldName]
		if !exists {
			return fmt.Errorf("context '%s' not found", oldName)
		}

		if _, exists := cfg.Contexts[newName]; exists {
			return fmt.Errorf("context '%s' already exists", newName)
		}

		cfg.Contexts[newName] = ctx
		delete(cfg.Contexts, oldName)

		if cfg.CurrentContext == oldName {
			cfg.CurrentContext = newName
		}

		if err := cfg.Save(); err != nil {
			return fmt.Errorf("save config: %w", err)
		}

		printer.Success("Renamed context '%s' to '%s'", oldName, newName)
		return nil
	},
}

func init() {
	// Set command flags
	contextSetCmd.Flags().StringVar(&ctxSetURL, "url", "", "Zitadel instance URL")
	contextSetCmd.Flags().StringVar(&ctxSetToken, "token", "", "Personal Access Token")
	contextSetCmd.Flags().BoolVar(&ctxSetInsecure, "insecure", false, "Skip TLS verification")
	contextSetCmd.Flags().StringVar(&ctxSetOrg, "organization", "", "Default organization")
	contextSetCmd.Flags().StringVar(&ctxSetProject, "project", "", "Default project")

	contextCmd.AddCommand(contextListCmd)
	contextCmd.AddCommand(contextCurrentCmd)
	contextCmd.AddCommand(contextUseCmd)
	contextCmd.AddCommand(contextSetCmd)
	contextCmd.AddCommand(contextDeleteCmd)
	contextCmd.AddCommand(contextRenameCmd)
}
