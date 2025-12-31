package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/roylee17/zitadel-cli/internal/output"
	"github.com/roylee17/zitadel-cli/internal/version"
)

var healthzCmd = &cobra.Command{
	Use:   "healthz",
	Short: "Check Zitadel health status",
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx, cancel := commandContext()
		defer cancel()

		spin := output.NewSpinner("Checking Zitadel health...")
		spin.Start()

		err := apiClient.Healthz(ctx)
		spin.Stop()
		if err != nil {
			printer.Error("Zitadel is unhealthy: %v", err)
			return err
		}

		printer.Success("Zitadel is healthy")
		return nil
	},
}

var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Show current user/context information",
	RunE: func(_ *cobra.Command, _ []string) error {
		printer.Header("Current Context")

		if cfg.CurrentContext == "" {
			printer.Info("No context is set")
		} else {
			configCtx := cfg.CurrentCtx()
			if configCtx != nil {
				printer.PrintKeyValue(map[string]string{
					"Context":      cfg.CurrentContext,
					"URL":          configCtx.URL,
					"Organization": configCtx.Organization,
					"Project":      configCtx.Project,
				})
			}
		}

		// Try to get authenticated user info if client is initialized
		if apiClient != nil {
			fmt.Println()
			printer.Header("Authenticated User")

			ctx, cancel := commandContext()
			defer cancel()

			err := apiClient.Healthz(ctx)
			if err != nil {
				printer.Warning("Cannot reach Zitadel: %v", err)
			} else {
				printer.Success("Connected to Zitadel")
			}
		}

		return nil
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(_ *cobra.Command, _ []string) {
		fmt.Println(version.Full())
	},
}
