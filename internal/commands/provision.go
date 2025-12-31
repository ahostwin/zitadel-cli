package commands

import (
	"fmt"
	"os"
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
  - A Chrome extension application (optional, PKCE flow)
  - A CLI application (optional, PKCE + Device Auth flow)
  - Custom or standard roles (admin, user, viewer)
  - An admin user (optional)

Examples:
  # Provision a project with default URLs
  zitadel-cli provision alpinetms \
    --frontend-url https://frontend.alpinetms.test \
    --backend-url https://backend.alpinetms.test

  # Provision with Chrome extension and CLI app
  zitadel-cli provision alpinetms \
    --frontend-url https://frontend.alpinetms.test \
    --backend-url https://backend.alpinetms.test \
    --chrome-extension-id abcdefghijklmnopqrstuvwxyzabcdef \
    --cli-app

  # Provision with custom roles
  zitadel-cli provision alpinetms \
    --frontend-url https://frontend.alpinetms.test \
    --backend-url https://backend.alpinetms.test \
    --roles admin,developer,researcher

  # Provision with Kubernetes output
  zitadel-cli provision alpinetms \
    --frontend-url https://frontend.alpinetms.test \
    --backend-url https://backend.alpinetms.test \
    --output-k8s-configmap \
    --output-k8s-secret \
    --output-file oidc-config.yaml

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
	provisionFrontendURL     string
	provisionBackendURL      string
	provisionDevMode         bool
	provisionCreateAdmin     bool
	provisionAdminEmail      string
	provisionAdminPassword   string
	provisionCreateRoles     bool
	provisionRoles           string
	provisionChromeExtID     string
	provisionCLIApp          bool
	provisionOutputK8sConfig bool
	provisionOutputK8sSecret bool
	provisionOutputFile      string
	provisionK8sNamespace    string
)

// ProvisionResult holds the result of provisioning.
type ProvisionResult struct {
	Project      *client.Project `json:"project"`
	FrontendApp  *client.App     `json:"frontendApp"`
	BackendApp   *client.App     `json:"backendApp"`
	ChromeExtApp *client.App     `json:"chromeExtApp,omitempty"`
	CLIApp       *client.App     `json:"cliApp,omitempty"`
	Roles        []client.Role   `json:"roles,omitempty"`
	AdminUser    *client.User    `json:"adminUser,omitempty"`
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

		var rolesToCreate []client.Role
		if provisionRoles != "" {
			// Parse custom roles from comma-separated string
			roleNames := strings.Split(provisionRoles, ",")
			for _, roleName := range roleNames {
				roleName = strings.TrimSpace(roleName)
				if roleName == "" {
					continue
				}
				rolesToCreate = append(rolesToCreate, client.Role{
					Key:         roleName,
					DisplayName: toDisplayName(roleName),
					Group:       "custom",
				})
			}
		} else {
			// Default roles
			rolesToCreate = []client.Role{
				{Key: "admin", DisplayName: "Administrator", Group: "admin"},
				{Key: "user", DisplayName: "Standard User", Group: "users"},
				{Key: "viewer", DisplayName: "Read-only Viewer", Group: "users"},
			}
		}

		var createdRoleNames []string
		for _, role := range rolesToCreate {
			err := apiClient.AddProjectRole(ctx, project.ID, role)
			if err != nil {
				// Role might already exist, continue
				if !strings.Contains(err.Error(), "already exists") {
					debugf("Warning: Failed to create role '%s': %v", role.Key, err)
				}
			}
			result.Roles = append(result.Roles, role)
			createdRoleNames = append(createdRoleNames, role.Key)
		}
		spin.Stop()
		printer.Success("Roles created: %s", strings.Join(createdRoleNames, ", "))
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

	// Step 5: Create Chrome extension app (if requested)
	if provisionChromeExtID != "" {
		spin = output.NewSpinner("Creating Chrome extension OIDC app...")
		spin.Start()

		chromeExtAppName := projectName + "-chrome-extension"

		var chromeExtApp *client.App
		for _, a := range apps {
			if a.Name == chromeExtAppName {
				chromeExtApp = &a
				break
			}
		}

		if chromeExtApp != nil {
			spin.Stop()
			printer.Info("Chrome extension app already exists (Client ID: %s)", chromeExtApp.ClientID)
		} else {
			// Chrome extension redirect URI format
			redirectURI := fmt.Sprintf("https://%s.chromiumapp.org/callback", provisionChromeExtID)

			chromeExtApp, err = apiClient.CreateOIDCApp(ctx, project.ID, client.OIDCAppConfig{
				Name:         chromeExtAppName,
				RedirectURIs: []string{redirectURI},
				AppType:      "spa", // Public client with PKCE
				DevMode:      provisionDevMode,
			})
			spin.Stop()
			if err != nil {
				return fmt.Errorf("failed to create Chrome extension app: %w", err)
			}
			printer.Success("Chrome extension app created (Client ID: %s)", chromeExtApp.ClientID)
		}
		result.ChromeExtApp = chromeExtApp
	}

	// Step 6: Create CLI app (if requested)
	if provisionCLIApp {
		spin = output.NewSpinner("Creating CLI OIDC app...")
		spin.Start()

		cliAppName := projectName + "-cli"

		var cliApp *client.App
		for _, a := range apps {
			if a.Name == cliAppName {
				cliApp = &a
				break
			}
		}

		if cliApp != nil {
			spin.Stop()
			printer.Info("CLI app already exists (Client ID: %s)", cliApp.ClientID)
		} else {
			// CLI app redirect URIs for localhost callback
			redirectURIs := []string{
				"http://localhost:8400/callback",
				"http://127.0.0.1:8400/callback",
			}

			cliApp, err = apiClient.CreateOIDCApp(ctx, project.ID, client.OIDCAppConfig{
				Name:         cliAppName,
				RedirectURIs: redirectURIs,
				AppType:      "native", // Native app with PKCE
				DevMode:      provisionDevMode,
				// Enable device auth flow along with auth code and refresh token
				GrantTypes: []string{
					"OIDC_GRANT_TYPE_AUTHORIZATION_CODE",
					"OIDC_GRANT_TYPE_REFRESH_TOKEN",
					"OIDC_GRANT_TYPE_DEVICE_CODE",
				},
			})
			spin.Stop()
			if err != nil {
				return fmt.Errorf("failed to create CLI app: %w", err)
			}
			printer.Success("CLI app created (Client ID: %s)", cliApp.ClientID)
		}
		result.CLIApp = cliApp
	}

	// Step 7: Create admin user (if requested)
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

	kvMap := map[string]string{
		"Project":  fmt.Sprintf("%s (ID: %s)", result.Project.Name, result.Project.ID),
		"Frontend": result.FrontendApp.ClientID,
		"Backend":  result.BackendApp.ClientID,
	}
	if result.ChromeExtApp != nil {
		kvMap["Chrome Ext"] = result.ChromeExtApp.ClientID
	}
	if result.CLIApp != nil {
		kvMap["CLI"] = result.CLIApp.ClientID
	}
	printer.PrintKeyValue(kvMap)

	fmt.Println()
	printer.Header("Environment Variables")
	fmt.Println()
	fmt.Printf("OIDC_ISSUER=%s\n", zitadelURL)
	fmt.Printf("OIDC_FRONTEND_CLIENT_ID=%s\n", result.FrontendApp.ClientID)
	fmt.Printf("OIDC_BACKEND_CLIENT_ID=%s\n", result.BackendApp.ClientID)
	if result.BackendApp.ClientSecret != "" {
		fmt.Printf("OIDC_BACKEND_CLIENT_SECRET=%s\n", result.BackendApp.ClientSecret)
	}
	if result.ChromeExtApp != nil {
		fmt.Printf("OIDC_CHROME_EXT_CLIENT_ID=%s\n", result.ChromeExtApp.ClientID)
	}
	if result.CLIApp != nil {
		fmt.Printf("OIDC_CLI_CLIENT_ID=%s\n", result.CLIApp.ClientID)
	}

	// Generate Kubernetes manifests if requested
	if provisionOutputK8sConfig || provisionOutputK8sSecret {
		fmt.Println()
		if err := outputK8sManifests(result); err != nil {
			return fmt.Errorf("failed to generate Kubernetes manifests: %w", err)
		}
	}

	return nil
}

// outputK8sManifests generates Kubernetes ConfigMap and/or Secret YAML manifests.
func outputK8sManifests(result *ProvisionResult) error {
	var manifests []string

	namespace := provisionK8sNamespace
	if namespace == "" {
		namespace = "default"
	}

	// Generate ConfigMap
	if provisionOutputK8sConfig {
		configMap := generateK8sConfigMap(result, namespace)
		manifests = append(manifests, configMap)
	}

	// Generate Secret
	if provisionOutputK8sSecret {
		secret := generateK8sSecret(result, namespace)
		manifests = append(manifests, secret)
	}

	output := strings.Join(manifests, "---\n")

	// Write to file or stdout
	if provisionOutputFile != "" {
		if err := os.WriteFile(provisionOutputFile, []byte(output), 0o600); err != nil {
			return fmt.Errorf("failed to write to file: %w", err)
		}
		printer.Success("Kubernetes manifests written to %s", provisionOutputFile)
	} else {
		printer.Header("Kubernetes Manifests")
		fmt.Println()
		fmt.Print(output)
	}

	return nil
}

// generateK8sConfigMap generates a Kubernetes ConfigMap YAML with non-sensitive config.
func generateK8sConfigMap(result *ProvisionResult, namespace string) string {
	var sb strings.Builder

	sb.WriteString("apiVersion: v1\n")
	sb.WriteString("kind: ConfigMap\n")
	sb.WriteString("metadata:\n")
	sb.WriteString(fmt.Sprintf("  name: %s-oidc-config\n", result.Project.Name))
	sb.WriteString(fmt.Sprintf("  namespace: %s\n", namespace))
	sb.WriteString("data:\n")
	sb.WriteString(fmt.Sprintf("  OIDC_ISSUER: %q\n", zitadelURL))
	sb.WriteString(fmt.Sprintf("  OIDC_FRONTEND_CLIENT_ID: %q\n", result.FrontendApp.ClientID))
	sb.WriteString(fmt.Sprintf("  OIDC_BACKEND_CLIENT_ID: %q\n", result.BackendApp.ClientID))

	if result.ChromeExtApp != nil {
		sb.WriteString(fmt.Sprintf("  OIDC_CHROME_EXT_CLIENT_ID: %q\n", result.ChromeExtApp.ClientID))
	}
	if result.CLIApp != nil {
		sb.WriteString(fmt.Sprintf("  OIDC_CLI_CLIENT_ID: %q\n", result.CLIApp.ClientID))
	}

	// Add well-known endpoints
	sb.WriteString(fmt.Sprintf("  OIDC_DISCOVERY_URL: %q\n", zitadelURL+"/.well-known/openid-configuration"))
	sb.WriteString(fmt.Sprintf("  OIDC_JWKS_URL: %q\n", zitadelURL+"/oauth/v2/keys"))

	return sb.String()
}

// generateK8sSecret generates a Kubernetes Secret YAML with sensitive data.
func generateK8sSecret(result *ProvisionResult, namespace string) string {
	var sb strings.Builder

	sb.WriteString("apiVersion: v1\n")
	sb.WriteString("kind: Secret\n")
	sb.WriteString("metadata:\n")
	sb.WriteString(fmt.Sprintf("  name: %s-oidc-secret\n", result.Project.Name))
	sb.WriteString(fmt.Sprintf("  namespace: %s\n", namespace))
	sb.WriteString("type: Opaque\n")
	sb.WriteString("stringData:\n")

	if result.BackendApp.ClientSecret != "" {
		sb.WriteString(fmt.Sprintf("  OIDC_BACKEND_CLIENT_SECRET: %q\n", result.BackendApp.ClientSecret))
	}

	return sb.String()
}

func init() {
	provisionCmd.Flags().StringVar(&provisionFrontendURL, "frontend-url", "", "Frontend application URL (required)")
	provisionCmd.Flags().StringVar(&provisionBackendURL, "backend-url", "", "Backend application URL (required)")
	provisionCmd.Flags().BoolVar(&provisionDevMode, "dev-mode", true, "Enable development mode for OIDC apps")
	provisionCmd.Flags().BoolVar(&provisionCreateRoles, "create-roles", true, "Create roles for the project")
	provisionCmd.Flags().StringVar(&provisionRoles, "roles", "", "Comma-separated list of custom roles (default: admin,user,viewer)")
	provisionCmd.Flags().BoolVar(&provisionCreateAdmin, "create-admin", false, "Create an admin user")
	provisionCmd.Flags().StringVar(&provisionAdminEmail, "admin-email", "", "Admin user email")
	provisionCmd.Flags().StringVar(&provisionAdminPassword, "admin-password", "", "Admin user password")

	// New flags for Chrome extension, CLI app, and Kubernetes output
	provisionCmd.Flags().StringVar(&provisionChromeExtID, "chrome-extension-id", "", "Chrome extension ID to create PKCE client for")
	provisionCmd.Flags().BoolVar(&provisionCLIApp, "cli-app", false, "Create a CLI application with PKCE + Device Auth flow")
	provisionCmd.Flags().BoolVar(&provisionOutputK8sConfig, "output-k8s-configmap", false, "Generate Kubernetes ConfigMap YAML")
	provisionCmd.Flags().BoolVar(&provisionOutputK8sSecret, "output-k8s-secret", false, "Generate Kubernetes Secret YAML")
	provisionCmd.Flags().StringVar(&provisionOutputFile, "output-file", "", "Write Kubernetes manifests to file instead of stdout")
	provisionCmd.Flags().StringVar(&provisionK8sNamespace, "k8s-namespace", "default", "Kubernetes namespace for generated manifests")

	_ = provisionCmd.MarkFlagRequired("frontend-url")
	_ = provisionCmd.MarkFlagRequired("backend-url")
}

// toDisplayName converts a role key like "admin_user" to a display name like "Admin User".
func toDisplayName(s string) string {
	// Replace underscores with spaces
	s = strings.ReplaceAll(s, "_", " ")
	// Capitalize first letter of each word
	words := strings.Fields(s)
	for i, word := range words {
		if len(word) > 0 {
			words[i] = strings.ToUpper(word[:1]) + strings.ToLower(word[1:])
		}
	}
	return strings.Join(words, " ")
}
