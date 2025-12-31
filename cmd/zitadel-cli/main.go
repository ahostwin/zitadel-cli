// Package main provides the entry point for the zitadel-cli tool.
package main

import (
	"os"

	"github.com/roylee17/zitadel-cli/internal/commands"
)

func main() {
	if err := commands.Execute(); err != nil {
		os.Exit(1)
	}
}
