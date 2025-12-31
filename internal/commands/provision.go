package commands

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/roylee17/zitadel-cli/internal/client"
	"github.com/roylee17/zitadel-cli/internal/output"
)

var provisionCmd = &cobra.Command{
	Use:   "provision <project-name>",
	Short: "Provision a complete project with OIDC apps",
	Long: `Provision a complete Zitadel project with frontend and backend OIDC applications.

This command creates:
  - A project with the given name
  - A frontend SPA application (PKCE flow)
  - A backend web application (client credentials)
  - Standard roles (admin, user, viewer)
  - An admin user (optional)

Examples:
  # Provision a project with default URLs
  zitadel-cli provision alpinetms \
    --frontend-url https://frontend.alpinetms.test \
    --backend-url https://backend.alpinetms.test

  # Provision with admin user
  zitadel-cli provision alpinetms \
    --frontend-url https://frontend.alpinetms.test \
    --backend-url https://backend.alpinetms.test \
    --create-admin \
    --admin-email admin@example.com \
    --admin-password Password123!`,
	Args: cobra.ExactArgs(1),
	RunE: runProvision,
}

var (
	provisionFrontendURL   string
	provisionBackendURL    string
	provisionDevMode       bool
	provisionCreateAdmin   bool
	provisionAdminEmail    string
	provisionAdminPassword string
	provisionCreateRoles   bool
)

// ProvisionResult holds the result of provisioning.
type ProvisionResult struct {
	Project     *client.Project `json:"project"`
	FrontendApp *client.App     `json:"frontendApp"`
	BackendApp  *client.App     `json:"backendApp"`
	Roles       []client.Role   `json:"roles,omitempty"`
	AdminUser   *client.User    `json:"adminUser,omitempty"`
}

func runProvision(_ *cobra.Command, args []string) error {
	ctx, cancel := commandContext()
	defer cancel()

	projectName := args[0]

	result := &ProvisionResult{}

	// Step 1: Create or get project
	spin := output.NewSpinner("Creating project...")
	spin.Start()

	project, err := apiClient.GetProjectByName(ctx, projectName)
	if err != nil {
		spin.Stop()
		return fmt.Errorf("failed to check existing project: %w", err)
	}
	if project != nil {
		spin.Stop()
		printer.Info("Project '%s' already exists (ID: %s)", projectName, project.ID)
	} else {
		project, err = apiClient.CreateProject(ctx, projectName)
		spin.Stop()
		if err != nil {
			return fmt.Errorf("failed to create project: %w", err)
		}
		printer.Success("Project '%s' created (ID: %s)", projectName, project.ID)
	}
	result.Project = project

	// Step 2: Create roles (if requested)
	if provisionCreateRoles {
		spin := output.NewSpinner("Creating roles...")
		spin.Start()

		standardRoles := []client.Role{
			{Key: "admin", DisplayName: "Administrator", Group: "admin"},
			{Key: "user", DisplayName: "Standard User", Group: "users"},
			{Key: "viewer", DisplayName: "Read-only Viewer", Group: "users"},
		}

		for _, role := range standardRoles {
			err := apiClient.AddProjectRole(ctx, project.ID, role)
			if err != nil {
				// Role might already exist, continue
				if !strings.Contains(err.Error(), "already exists") {
					debugf("Warning: Failed to create role '%s': %v", role.Key, err)
				}
			}
			result.Roles = append(result.Roles, role)
		}
		spin.Stop()
		printer.Success("Roles created: admin, user, viewer")
	}

	// Step 3: Create frontend app (SPA with PKCE)
	spin = output.NewSpinner("Creating frontend OIDC app...")
	spin.Start()

	frontendAppName := projectName + "-frontend"

	// Check if app exists
	apps, err := apiClient.ListApps(ctx, project.ID)
	if err != nil {
		spin.Stop()
		return fmt.Errorf("failed to list apps: %w", err)
	}

	var frontendApp *client.App
	for _, a := range apps {
		if a.Name == frontendAppName {
			frontendApp = &a
			break
		}
	}

	if frontendApp != nil {
		spin.Stop()
		printer.Info("Frontend app already exists (Client ID: %s)", frontendApp.ClientID)
	} else {
		redirectURI := provisionFrontendURL + "/callback"
		silentRenewURI := provisionFrontendURL + "/silent-renew"
		postLogoutURI := provisionFrontendURL

		frontendApp, err = apiClient.CreateOIDCApp(ctx, project.ID, client.OIDCAppConfig{
			Name:                   frontendAppName,
			RedirectURIs:           []string{redirectURI, silentRenewURI},
			PostLogoutRedirectURIs: []string{postLogoutURI},
			AppType:                "spa",
			DevMode:                provisionDevMode,
		})
		spin.Stop()
		if err != nil {
			return fmt.Errorf("failed to create frontend app: %w", err)
		}
		printer.Success("Frontend app created (Client ID: %s)", frontendApp.ClientID)
	}
	result.FrontendApp = frontendApp

	// Step 4: Create backend app (Web/Confidential)
	spin = output.NewSpinner("Creating backend OIDC app...")
	spin.Start()

	backendAppName := projectName + "-backend"

	var backendApp *client.App
	for _, a := range apps {
		if a.Name == backendAppName {
			backendApp = &a
			break
		}
	}

	if backendApp != nil {
		spin.Stop()
		printer.Info("Backend app already exists (Client ID: %s)", backendApp.ClientID)

		// Regenerate secret for existing app
		spin = output.NewSpinner("Regenerating client secret...")
		spin.Start()
		secret, err := apiClient.RegenerateClientSecret(ctx, project.ID, backendApp.ID)
		spin.Stop()
		if err != nil {
			printer.Warning("Failed to regenerate secret: %v", err)
		} else {
			backendApp.ClientSecret = secret
			printer.Success("Regenerated client secret")
		}
	} else {
		redirectURI := provisionBackendURL + "/auth/callback"
		postLogoutURI := provisionBackendURL

		backendApp, err = apiClient.CreateOIDCApp(ctx, project.ID, client.OIDCAppConfig{
			Name:                   backendAppName,
			RedirectURIs:           []string{redirectURI},
			PostLogoutRedirectURIs: []string{postLogoutURI},
			AppType:                "web",
			DevMode:                provisionDevMode,
		})
		spin.Stop()
		if err != nil {
			return fmt.Errorf("failed to create backend app: %w", err)
		}
		printer.Success("Backend app created (Client ID: %s)", backendApp.ClientID)
	}
	result.BackendApp = backendApp

	// Step 5: Create admin user (if requested)
	if provisionCreateAdmin {
		if provisionAdminEmail == "" || provisionAdminPassword == "" {
			return fmt.Errorf("--admin-email and --admin-password are required when --create-admin is set")
		}

		spin := output.NewSpinner("Creating admin user...")
		spin.Start()

		adminUsername := "admin"

		existingUser, err := apiClient.GetUserByUsername(ctx, adminUsername)
		if err != nil {
			spin.Stop()
			return fmt.Errorf("failed to check existing admin user: %w", err)
		}

		if existingUser != nil {
			spin.Stop()
			printer.Info("Admin user already exists (ID: %s)", existingUser.ID)
			result.AdminUser = existingUser
		} else {
			adminUser, err := apiClient.CreateUser(ctx, client.CreateUserConfig{
				Username:  adminUsername,
				Email:     provisionAdminEmail,
				FirstName: "Admin",
				LastName:  "User",
				Password:  provisionAdminPassword,
			})
			spin.Stop()
			if err != nil {
				return fmt.Errorf("failed to create admin user: %w", err)
			}
			printer.Success("Admin user created (ID: %s)", adminUser.ID)
			result.AdminUser = adminUser

			// Grant admin role
			if provisionCreateRoles {
				err = apiClient.GrantUserProjectRoles(ctx, project.ID, adminUser.ID, []string{"admin"})
				if err != nil {
					printer.Warning("Failed to grant admin role: %v", err)
				} else {
					printer.Success("Granted admin role to user")
				}
			}
		}
	}

	// Output results
	fmt.Println()
	printer.Header("Provisioning Complete")
	fmt.Println()

	printer.PrintKeyValue(map[string]string{
		"Project":  fmt.Sprintf("%s (ID: %s)", result.Project.Name, result.Project.ID),
		"Frontend": result.FrontendApp.ClientID,
		"Backend":  result.BackendApp.ClientID,
	})

	fmt.Println()
	printer.Header("Environment Variables")
	fmt.Println()
	fmt.Printf("OIDC_ISSUER=%s\n", zitadelURL)
	fmt.Printf("OIDC_FRONTEND_CLIENT_ID=%s\n", result.FrontendApp.ClientID)
	fmt.Printf("OIDC_BACKEND_CLIENT_ID=%s\n", result.BackendApp.ClientID)
	if result.BackendApp.ClientSecret != "" {
		fmt.Printf("OIDC_BACKEND_CLIENT_SECRET=%s\n", result.BackendApp.ClientSecret)
	}

	return nil
}

func init() {
	provisionCmd.Flags().StringVar(&provisionFrontendURL, "frontend-url", "", "Frontend application URL (required)")
	provisionCmd.Flags().StringVar(&provisionBackendURL, "backend-url", "", "Backend application URL (required)")
	provisionCmd.Flags().BoolVar(&provisionDevMode, "dev-mode", true, "Enable development mode for OIDC apps")
	provisionCmd.Flags().BoolVar(&provisionCreateRoles, "create-roles", true, "Create standard roles (admin, user, viewer)")
	provisionCmd.Flags().BoolVar(&provisionCreateAdmin, "create-admin", false, "Create an admin user")
	provisionCmd.Flags().StringVar(&provisionAdminEmail, "admin-email", "", "Admin user email")
	provisionCmd.Flags().StringVar(&provisionAdminPassword, "admin-password", "", "Admin user password")

	_ = provisionCmd.MarkFlagRequired("frontend-url")
	_ = provisionCmd.MarkFlagRequired("backend-url")
}
