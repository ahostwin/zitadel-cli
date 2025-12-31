package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/roylee17/zitadel-cli/internal/client"
	"github.com/roylee17/zitadel-cli/internal/output"
)

var machineCmd = &cobra.Command{
	Use:   "machine",
	Short: "Manage machine users (service accounts)",
	Long:  "Commands for managing machine users (service accounts) for automation.",
}

var (
	machineName        string
	machineDescription string
)

var machineListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List machine users",
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx, cancel := commandContext()
		defer cancel()

		spin := output.NewSpinner("Fetching machine users...")
		spin.Start()

		users, err := apiClient.ListMachineUsers(ctx)
		spin.Stop()
		if err != nil {
			return fmt.Errorf("failed to list machine users: %w", err)
		}

		if len(users) == 0 {
			printer.Info("No machine users found")
			return nil
		}

		return output.PrintTable(printer, []string{"ID", "USERNAME", "NAME", "STATE"}, users, func(u client.MachineUser) []string {
			return []string{u.ID, u.Username, u.Name, u.State}
		})
	},
}

var machineGetCmd = &cobra.Command{
	Use:   "get <username>",
	Short: "Get machine user by username",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		ctx, cancel := commandContext()
		defer cancel()

		spin := output.NewSpinner("Fetching machine user...")
		spin.Start()

		user, err := apiClient.GetMachineUserByUsername(ctx, args[0])
		spin.Stop()
		if err != nil {
			return fmt.Errorf("failed to get machine user: %w", err)
		}
		if user == nil {
			return fmt.Errorf("machine user '%s' not found", args[0])
		}

		return printer.PrintObject(user)
	},
}

var machineCreateCmd = &cobra.Command{
	Use:   "create <username>",
	Short: "Create a machine user (service account)",
	Long: `Create a machine user for automation purposes.

Examples:
  # Create a service account
  zitadel-cli machine create ci-bot \
    --name "CI/CD Bot" \
    --description "Service account for CI/CD automation"`,
	Args: cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		ctx, cancel := commandContext()
		defer cancel()

		spin := output.NewSpinner("Checking existing machine user...")
		spin.Start()

		// Check if machine user already exists
		existing, err := apiClient.GetMachineUserByUsername(ctx, args[0])
		if err != nil {
			spin.Stop()
			return fmt.Errorf("failed to check existing machine user: %w", err)
		}
		if existing != nil {
			spin.Stop()
			printer.Warning("Machine user '%s' already exists (ID: %s)", args[0], existing.ID)
			return printer.PrintObject(existing)
		}

		name := machineName
		if name == "" {
			name = args[0]
		}

		spin.UpdateMessage("Creating machine user...")
		user, err := apiClient.CreateMachineUser(ctx, args[0], name, machineDescription)
		spin.Stop()
		if err != nil {
			return fmt.Errorf("failed to create machine user: %w", err)
		}

		printer.Success("Machine user '%s' created", user.Username)
		return printer.PrintObject(user)
	},
}

var machineDeleteCmd = &cobra.Command{
	Use:   "delete <user-id>",
	Short: "Delete a machine user",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		if !confirmDanger(fmt.Sprintf("Delete machine user '%s'?", args[0])) {
			printer.Info("Cancelled")
			return nil
		}

		ctx, cancel := commandContext()
		defer cancel()

		spin := output.NewSpinner("Deleting machine user...")
		spin.Start()

		err := apiClient.DeleteUser(ctx, args[0])
		spin.Stop()
		if err != nil {
			return fmt.Errorf("failed to delete machine user: %w", err)
		}

		printer.Success("Machine user '%s' deleted", args[0])
		return nil
	},
}

func init() {
	// Create command flags
	machineCreateCmd.Flags().StringVar(&machineName, "name", "", "Display name")
	machineCreateCmd.Flags().StringVar(&machineDescription, "description", "", "Description")

	machineCmd.AddCommand(machineListCmd)
	machineCmd.AddCommand(machineGetCmd)
	machineCmd.AddCommand(machineCreateCmd)
	machineCmd.AddCommand(machineDeleteCmd)
}
