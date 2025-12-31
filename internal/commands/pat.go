package commands

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/roylee17/zitadel-cli/internal/client"
	"github.com/roylee17/zitadel-cli/internal/output"
)

var patCmd = &cobra.Command{
	Use:   "pat",
	Short: "Manage Personal Access Tokens",
	Long:  "Commands for managing Personal Access Tokens (PATs) for users.",
}

var (
	patUserID         string
	patUsername       string
	patExpirationDays int
)

var patListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List PATs for a user",
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx, cancel := commandContext()
		defer cancel()

		userID, err := resolveUserID(ctx, patUserID, patUsername)
		if err != nil {
			return err
		}

		spin := output.NewSpinner("Fetching PATs...")
		spin.Start()

		pats, err := apiClient.ListPATs(ctx, userID)
		spin.Stop()
		if err != nil {
			return fmt.Errorf("failed to list PATs: %w", err)
		}

		if len(pats) == 0 {
			printer.Info("No PATs found for user")
			return nil
		}

		return output.PrintTable(printer, []string{"ID", "EXPIRATION"}, pats, func(p client.PAT) []string {
			return []string{p.ID, p.Expiration}
		})
	},
}

var patCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a PAT for a user",
	Long: `Create a Personal Access Token for authentication.

Examples:
  # Create a PAT for a machine user (1 year expiration)
  zitadel-cli pat create --username iam-admin --expiration-days 365

  # Create a PAT with user ID
  zitadel-cli pat create --user-id 123456789 --expiration-days 90`,
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx, cancel := commandContext()
		defer cancel()

		userID, err := resolveUserID(ctx, patUserID, patUsername)
		if err != nil {
			return err
		}

		spin := output.NewSpinner("Creating PAT...")
		spin.Start()

		pat, err := apiClient.CreatePAT(ctx, userID, patExpirationDays)
		spin.Stop()
		if err != nil {
			return fmt.Errorf("failed to create PAT: %w", err)
		}

		printer.Success("PAT created")
		printer.PrintKeyValue(map[string]string{
			"ID":         pat.ID,
			"Token":      pat.Token,
			"Expiration": pat.Expiration,
		})
		printer.Warning("IMPORTANT: Save this token now. It cannot be retrieved later!")

		return nil
	},
}

var patDeleteCmd = &cobra.Command{
	Use:   "delete <pat-id>",
	Short: "Delete a PAT",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		if !confirmAction(fmt.Sprintf("Delete PAT '%s'?", args[0])) {
			printer.Info("Cancelled")
			return nil
		}

		ctx, cancel := commandContext()
		defer cancel()

		userID, err := resolveUserID(ctx, patUserID, patUsername)
		if err != nil {
			return err
		}

		spin := output.NewSpinner("Deleting PAT...")
		spin.Start()

		err = apiClient.DeletePAT(ctx, userID, args[0])
		spin.Stop()
		if err != nil {
			return fmt.Errorf("failed to delete PAT: %w", err)
		}

		printer.Success("PAT '%s' deleted", args[0])
		return nil
	},
}

// resolveUserID resolves user ID from either direct ID or username.
func resolveUserID(ctx context.Context, userID, username string) (string, error) {
	if userID != "" {
		return userID, nil
	}
	if username == "" {
		return "", fmt.Errorf("either --user-id or --username is required")
	}

	// Try human user first
	user, err := apiClient.GetUserByUsername(ctx, username)
	if err != nil {
		return "", fmt.Errorf("failed to find user: %w", err)
	}
	if user != nil {
		return user.ID, nil
	}

	// Try machine user
	machine, err := apiClient.GetMachineUserByUsername(ctx, username)
	if err != nil {
		return "", fmt.Errorf("failed to find machine user: %w", err)
	}
	if machine != nil {
		return machine.ID, nil
	}

	return "", fmt.Errorf("user '%s' not found", username)
}

func init() {
	// List command flags
	patListCmd.Flags().StringVar(&patUserID, "user-id", "", "User ID")
	patListCmd.Flags().StringVar(&patUsername, "username", "", "Username")

	// Create command flags
	patCreateCmd.Flags().StringVar(&patUserID, "user-id", "", "User ID")
	patCreateCmd.Flags().StringVar(&patUsername, "username", "", "Username")
	patCreateCmd.Flags().IntVar(&patExpirationDays, "expiration-days", 365, "Days until expiration")

	// Delete command flags
	patDeleteCmd.Flags().StringVar(&patUserID, "user-id", "", "User ID")
	patDeleteCmd.Flags().StringVar(&patUsername, "username", "", "Username")

	patCmd.AddCommand(patListCmd)
	patCmd.AddCommand(patCreateCmd)
	patCmd.AddCommand(patDeleteCmd)
}
