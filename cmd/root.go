// Package cmd implements the envcrypt CLI.
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "envcrypt",
	Short: "Encrypt and version-control .env files using age encryption",
	Long: `envcrypt is a lightweight utility to encrypt .env files using age encryption
with team key management, making it safe to commit secrets to version control.`,
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
