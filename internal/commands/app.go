package commands

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/roylee17/zitadel-cli/internal/client"
	"github.com/roylee17/zitadel-cli/internal/output"
)

var appCmd = &cobra.Command{
	Use:   "app",
	Short: "Manage applications",
	Long:  "Commands for managing OIDC and API applications within projects.",
}

var (
	appProjectID              string
	appProjectName            string
	appType                   string
	appRedirectURIs           []string
	appPostLogoutRedirectURIs []string
	appDevMode                bool
)

var appListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List applications in a project",
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx, cancel := commandContext()
		defer cancel()

		projectID, err := resolveProjectID(ctx, appProjectID, appProjectName)
		if err != nil {
			return err
		}

		spin := output.NewSpinner("Fetching applications...")
		spin.Start()

		apps, err := apiClient.ListApps(ctx, projectID)
		spin.Stop()
		if err != nil {
			return fmt.Errorf("failed to list apps: %w", err)
		}

		if len(apps) == 0 {
			printer.Info("No applications found in project")
			return nil
		}

		return output.PrintTable(printer, []string{"ID", "NAME", "TYPE", "CLIENT_ID"}, apps, func(a client.App) []string {
			return []string{a.ID, a.Name, a.Type, a.ClientID}
		})
	},
}

var appGetCmd = &cobra.Command{
	Use:   "get <app-id>",
	Short: "Get application details",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		ctx, cancel := commandContext()
		defer cancel()

		projectID, err := resolveProjectID(ctx, appProjectID, appProjectName)
		if err != nil {
			return err
		}

		spin := output.NewSpinner("Fetching application...")
		spin.Start()

		apps, err := apiClient.ListApps(ctx, projectID)
		spin.Stop()
		if err != nil {
			return fmt.Errorf("failed to fetch apps: %w", err)
		}

		var app *client.App
		for _, a := range apps {
			if a.ID == args[0] || a.Name == args[0] {
				app = &a
				break
			}
		}

		if app == nil {
			return fmt.Errorf("application '%s' not found", args[0])
		}

		return printer.PrintObject(app)
	},
}

var appCreateOIDCCmd = &cobra.Command{
	Use:   "create-oidc <name>",
	Short: "Create an OIDC application",
	Long: `Create an OIDC application in a project.

App types:
  - web: Confidential client (server-side app with client secret)
  - spa: Public client (browser app using PKCE)
  - native: Public client (mobile/desktop app using PKCE)

Examples:
  # Create a SPA frontend app
  zitadel-cli app create-oidc myapp-frontend \
    --project alpinetms \
    --type spa \
    --redirect-uri "https://frontend.alpinetms.test/callback" \
    --post-logout-uri "https://frontend.alpinetms.test"

  # Create a confidential backend app
  zitadel-cli app create-oidc myapp-backend \
    --project alpinetms \
    --type web \
    --redirect-uri "https://backend.alpinetms.test/auth/callback"`,
	Args: cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		ctx, cancel := commandContext()
		defer cancel()

		projectID, err := resolveProjectID(ctx, appProjectID, appProjectName)
		if err != nil {
			return err
		}

		if len(appRedirectURIs) == 0 {
			return fmt.Errorf("at least one --redirect-uri is required")
		}

		spin := output.NewSpinner("Creating OIDC application...")
		spin.Start()

		cfg := client.OIDCAppConfig{
			Name:                   args[0],
			RedirectURIs:           appRedirectURIs,
			PostLogoutRedirectURIs: appPostLogoutRedirectURIs,
			AppType:                appType,
			DevMode:                appDevMode,
		}

		app, err := apiClient.CreateOIDCApp(ctx, projectID, cfg)
		spin.Stop()
		if err != nil {
			return fmt.Errorf("failed to create OIDC app: %w", err)
		}

		printer.Success("OIDC Application '%s' created", app.Name)
		printer.PrintKeyValue(map[string]string{
			"ID":            app.ID,
			"Name":          app.Name,
			"Client ID":     app.ClientID,
			"Client Secret": app.ClientSecret,
			"Redirect URIs": strings.Join(app.RedirectURIs, ", "),
		})

		if app.ClientSecret != "" {
			printer.Warning("Save the client secret now - it cannot be retrieved later!")
		}

		return nil
	},
}

var appRegenerateSecretCmd = &cobra.Command{
	Use:   "regenerate-secret <app-id>",
	Short: "Regenerate client secret for an application",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		if !confirmAction("Regenerate client secret? This will invalidate the current secret.") {
			printer.Info("Cancelled")
			return nil
		}

		ctx, cancel := commandContext()
		defer cancel()

		projectID, err := resolveProjectID(ctx, appProjectID, appProjectName)
		if err != nil {
			return err
		}

		spin := output.NewSpinner("Regenerating client secret...")
		spin.Start()

		secret, err := apiClient.RegenerateClientSecret(ctx, projectID, args[0])
		spin.Stop()
		if err != nil {
			return fmt.Errorf("failed to regenerate secret: %w", err)
		}

		printer.Success("Client secret regenerated")
		printer.PrintKeyValue(map[string]string{
			"Client Secret": secret,
		})
		printer.Warning("Save this secret now - it cannot be retrieved later!")

		return nil
	},
}

var appDeleteCmd = &cobra.Command{
	Use:   "delete <app-id>",
	Short: "Delete an application",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		if !confirmDanger(fmt.Sprintf("Delete application '%s'?", args[0])) {
			printer.Info("Cancelled")
			return nil
		}

		ctx, cancel := commandContext()
		defer cancel()

		projectID, err := resolveProjectID(ctx, appProjectID, appProjectName)
		if err != nil {
			return err
		}

		spin := output.NewSpinner("Deleting application...")
		spin.Start()

		err = apiClient.DeleteApp(ctx, projectID, args[0])
		spin.Stop()
		if err != nil {
			return fmt.Errorf("failed to delete app: %w", err)
		}

		printer.Success("Application '%s' deleted", args[0])
		return nil
	},
}

// resolveProjectID resolves project ID from either direct ID or project name.
func resolveProjectID(ctx context.Context, projectID, projectName string) (string, error) {
	if projectID != "" {
		return projectID, nil
	}
	if projectName == "" {
		return "", fmt.Errorf("either --project-id or --project is required")
	}

	project, err := apiClient.GetProjectByName(ctx, projectName)
	if err != nil {
		return "", fmt.Errorf("failed to find project: %w", err)
	}
	if project == nil {
		return "", fmt.Errorf("project '%s' not found", projectName)
	}
	return project.ID, nil
}

func init() {
	// List command flags
	appListCmd.Flags().StringVar(&appProjectID, "project-id", "", "Project ID")
	appListCmd.Flags().StringVar(&appProjectName, "project", "", "Project name")

	// Get command flags
	appGetCmd.Flags().StringVar(&appProjectID, "project-id", "", "Project ID")
	appGetCmd.Flags().StringVar(&appProjectName, "project", "", "Project name")

	// Create OIDC command flags
	appCreateOIDCCmd.Flags().StringVar(&appProjectID, "project-id", "", "Project ID")
	appCreateOIDCCmd.Flags().StringVar(&appProjectName, "project", "", "Project name")
	appCreateOIDCCmd.Flags().StringVar(&appType, "type", "web", "App type: web, spa, or native")
	appCreateOIDCCmd.Flags().StringArrayVar(&appRedirectURIs, "redirect-uri", nil, "Redirect URI (can be specified multiple times)")
	appCreateOIDCCmd.Flags().StringArrayVar(&appPostLogoutRedirectURIs, "post-logout-uri", nil, "Post-logout redirect URI (can be specified multiple times)")
	appCreateOIDCCmd.Flags().BoolVar(&appDevMode, "dev-mode", true, "Enable development mode (relaxed security)")

	// Regenerate secret command flags
	appRegenerateSecretCmd.Flags().StringVar(&appProjectID, "project-id", "", "Project ID")
	appRegenerateSecretCmd.Flags().StringVar(&appProjectName, "project", "", "Project name")

	// Delete command flags
	appDeleteCmd.Flags().StringVar(&appProjectID, "project-id", "", "Project ID")
	appDeleteCmd.Flags().StringVar(&appProjectName, "project", "", "Project name")

	appCmd.AddCommand(appListCmd)
	appCmd.AddCommand(appGetCmd)
	appCmd.AddCommand(appCreateOIDCCmd)
	appCmd.AddCommand(appRegenerateSecretCmd)
	appCmd.AddCommand(appDeleteCmd)
}
