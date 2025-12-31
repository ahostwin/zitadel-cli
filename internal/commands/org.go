package commands

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/roylee17/zitadel-cli/internal/client"
	"github.com/roylee17/zitadel-cli/internal/output"
)

var orgCmd = &cobra.Command{
	Use:     "org",
	Aliases: []string{"organization"},
	Short:   "Manage organizations",
	Long:    "Commands for managing Zitadel organizations.",
}

var orgListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List all organizations",
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx, cancel := commandContext()
		defer cancel()

		spin := output.NewSpinner("Fetching organizations...")
		spin.Start()

		orgs, err := apiClient.ListOrgs(ctx)
		spin.Stop()
		if err != nil {
			return fmt.Errorf("failed to list organizations: %w", err)
		}

		if len(orgs) == 0 {
			printer.Info("No organizations found")
			return nil
		}

		return output.PrintTable(printer, []string{"ID", "NAME", "STATE"}, orgs, func(o client.Org) []string {
			return []string{o.ID, o.Name, o.State}
		})
	},
}

var orgGetCmd = &cobra.Command{
	Use:   "get <name>",
	Short: "Get organization by name",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		ctx, cancel := commandContext()
		defer cancel()

		spin := output.NewSpinner("Fetching organization...")
		spin.Start()

		org, err := apiClient.GetOrgByName(ctx, args[0])
		spin.Stop()
		if err != nil {
			return fmt.Errorf("failed to get organization: %w", err)
		}
		if org == nil {
			return fmt.Errorf("organization '%s' not found", args[0])
		}

		return printer.PrintObject(org)
	},
}

var orgCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create a new organization",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		return createOrGetResource(createResourceParams{
			resourceType: "Organization",
			name:         args[0],
			getExisting: func(ctx context.Context, name string) (namedResource, error) {
				return apiClient.GetOrgByName(ctx, name)
			},
			create: func(ctx context.Context, name string) (namedResource, error) {
				return apiClient.CreateOrg(ctx, name)
			},
		})
	},
}

func init() {
	orgCmd.AddCommand(orgListCmd)
	orgCmd.AddCommand(orgGetCmd)
	orgCmd.AddCommand(orgCreateCmd)
}
