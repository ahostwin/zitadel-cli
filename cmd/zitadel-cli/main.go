// Package main provides the entry point for the zitadel-cli tool.
package main

import (
	"fmt"
	"os"

	"github.com/roylee17/zitadel-cli/internal/commands"
)

func main() {
	if err := commands.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
