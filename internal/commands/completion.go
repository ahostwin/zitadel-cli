// Package commands provides CLI command implementations.
package commands

import (
	"os"

	"github.com/spf13/cobra"
)

var completionCmd = &cobra.Command{
	Use:   "completion [bash|zsh|fish|powershell]",
	Short: "Generate shell completion scripts",
	Long: `Generate shell completion scripts for zitadel-cli.

To load completions:

Bash:
  $ source <(zitadel-cli completion bash)
  # To load completions for each session, execute once:
  # Linux:
  $ zitadel-cli completion bash > /etc/bash_completion.d/zitadel-cli
  # macOS:
  $ zitadel-cli completion bash > $(brew --prefix)/etc/bash_completion.d/zitadel-cli

Zsh:
  $ source <(zitadel-cli completion zsh)
  # To load completions for each session, execute once:
  $ zitadel-cli completion zsh > "${fpath[1]}/_zitadel-cli"

Fish:
  $ zitadel-cli completion fish | source
  # To load completions for each session, execute once:
  $ zitadel-cli completion fish > ~/.config/fish/completions/zitadel-cli.fish

PowerShell:
  PS> zitadel-cli completion powershell | Out-String | Invoke-Expression
  # To load completions for each session, execute once:
  PS> zitadel-cli completion powershell > zitadel-cli.ps1
  # and source this file from your PowerShell profile.
`,
	DisableFlagsInUseLine: true,
	ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
	Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	RunE: func(cmd *cobra.Command, args []string) error {
		switch args[0] {
		case "bash":
			return cmd.Root().GenBashCompletion(os.Stdout)
		case "zsh":
			return cmd.Root().GenZshCompletion(os.Stdout)
		case "fish":
			return cmd.Root().GenFishCompletion(os.Stdout, true)
		case "powershell":
			return cmd.Root().GenPowerShellCompletionWithDesc(os.Stdout)
		}
		return nil
	},
}
