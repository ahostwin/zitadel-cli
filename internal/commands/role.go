package commands

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/roylee17/zitadel-cli/internal/client"
	"github.com/roylee17/zitadel-cli/internal/output"
)

var roleCmd = &cobra.Command{
	Use:   "role",
	Short: "Manage project roles",
	Long:  "Commands for managing roles within projects.",
}

var (
	roleProjectID   string
	roleProjectName string
	roleDisplayName string
	roleGroup       string
)

var roleListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List roles in a project",
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx, cancel := commandContext()
		defer cancel()

		projectID, err := resolveProjectID(ctx, roleProjectID, roleProjectName)
		if err != nil {
			return err
		}

		spin := output.NewSpinner("Fetching roles...")
		spin.Start()

		roles, err := apiClient.ListProjectRoles(ctx, projectID)
		spin.Stop()
		if err != nil {
			return fmt.Errorf("failed to list roles: %w", err)
		}

		if len(roles) == 0 {
			printer.Info("No roles found in project")
			return nil
		}

		return output.PrintTable(printer, []string{"KEY", "DISPLAY_NAME", "GROUP"}, roles, func(r client.Role) []string {
			return []string{r.Key, r.DisplayName, r.Group}
		})
	},
}

var roleCreateCmd = &cobra.Command{
	Use:   "create <key>",
	Short: "Create a project role",
	Long: `Create a new role in a project.

Examples:
  # Create an admin role
  zitadel-cli role create admin \
    --project alpinetms \
    --display-name "Administrator" \
    --group "admin"

  # Create a viewer role
  zitadel-cli role create viewer \
    --project alpinetms \
    --display-name "Read-only Viewer"`,
	Args: cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		ctx, cancel := commandContext()
		defer cancel()

		projectID, err := resolveProjectID(ctx, roleProjectID, roleProjectName)
		if err != nil {
			return err
		}

		displayName := roleDisplayName
		if displayName == "" {
			displayName = args[0]
		}

		spin := output.NewSpinner("Creating role...")
		spin.Start()

		role := client.Role{
			Key:         args[0],
			DisplayName: displayName,
			Group:       roleGroup,
		}

		err = apiClient.AddProjectRole(ctx, projectID, role)
		spin.Stop()
		if err != nil {
			return fmt.Errorf("failed to create role: %w", err)
		}

		printer.Success("Role '%s' created", role.Key)
		return printer.PrintObject(role)
	},
}

var roleGrantCmd = &cobra.Command{
	Use:   "grant <user-id> <role-key>...",
	Short: "Grant roles to a user",
	Long: `Grant one or more roles to a user.

Examples:
  # Grant admin role to a user
  zitadel-cli role grant 123456789 admin --project alpinetms

  # Grant multiple roles
  zitadel-cli role grant 123456789 admin viewer --project alpinetms`,
	Args: cobra.MinimumNArgs(2),
	RunE: func(_ *cobra.Command, args []string) error {
		ctx, cancel := commandContext()
		defer cancel()

		projectID, err := resolveProjectID(ctx, roleProjectID, roleProjectName)
		if err != nil {
			return err
		}

		userID := args[0]
		roleKeys := args[1:]

		spin := output.NewSpinner("Granting roles...")
		spin.Start()

		err = apiClient.GrantUserProjectRoles(ctx, projectID, userID, roleKeys)
		spin.Stop()
		if err != nil {
			return fmt.Errorf("failed to grant roles: %w", err)
		}

		printer.Success("Granted roles to user '%s'", userID)
		printer.Info("Roles: %s", strings.Join(roleKeys, ", "))
		return nil
	},
}

func init() {
	// List command flags
	roleListCmd.Flags().StringVar(&roleProjectID, "project-id", "", "Project ID")
	roleListCmd.Flags().StringVar(&roleProjectName, "project", "", "Project name")

	// Create command flags
	roleCreateCmd.Flags().StringVar(&roleProjectID, "project-id", "", "Project ID")
	roleCreateCmd.Flags().StringVar(&roleProjectName, "project", "", "Project name")
	roleCreateCmd.Flags().StringVar(&roleDisplayName, "display-name", "", "Display name")
	roleCreateCmd.Flags().StringVar(&roleGroup, "group", "", "Role group")

	// Grant command flags
	roleGrantCmd.Flags().StringVar(&roleProjectID, "project-id", "", "Project ID")
	roleGrantCmd.Flags().StringVar(&roleProjectName, "project", "", "Project name")

	roleCmd.AddCommand(roleListCmd)
	roleCmd.AddCommand(roleCreateCmd)
	roleCmd.AddCommand(roleGrantCmd)
}
