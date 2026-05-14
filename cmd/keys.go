package cmd

import (
	"fmt"

	"github.com/envcrypt/envcrypt/internal/keystore"
	"github.com/spf13/cobra"
)

var keystorePath string

var keysCmd = &cobra.Command{
	Use:   "keys",
	Short: "Manage team recipient keys",
}

var keysAddCmd = &cobra.Command{
	Use:   "add <alias> <public-key>",
	Short: "Add or update a recipient's public key",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		ks, err := keystore.Load(keystorePath)
		if err != nil {
			return fmt.Errorf("loading keystore: %w", err)
		}
		ks.Add(args[0], args[1])
		if err := ks.Save(); err != nil {
			return fmt.Errorf("saving keystore: %w", err)
		}
		fmt.Printf("Added recipient %q\n", args[0])
		return nil
	},
}

var keysRemoveCmd = &cobra.Command{
	Use:   "remove <alias>",
	Short: "Remove a recipient by alias",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ks, err := keystore.Load(keystorePath)
		if err != nil {
			return fmt.Errorf("loading keystore: %w", err)
		}
		if !ks.Remove(args[0]) {
			return fmt.Errorf("recipient %q not found", args[0])
		}
		if err := ks.Save(); err != nil {
			return fmt.Errorf("saving keystore: %w", err)
		}
		fmt.Printf("Removed recipient %q\n", args[0])
		return nil
	},
}

var keysListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all registered recipients",
	RunE: func(cmd *cobra.Command, args []string) error {
		ks, err := keystore.Load(keystorePath)
		if err != nil {
			return fmt.Errorf("loading keystore: %w", err)
		}
		if len(ks.Recipients) == 0 {
			fmt.Println("No recipients registered.")
			return nil
		}
		for _, r := range ks.Recipients {
			fmt.Printf("%-20s %s\n", r.Alias, r.PublicKey)
		}
		return nil
	},
}

func init() {
	keysCmd.PersistentFlags().StringVar(&keystorePath, "keystore", "", "path to keystore file (default: .envcrypt/keys.json)")
	keysCmd.AddCommand(keysAddCmd, keysRemoveCmd, keysListCmd)
	rootCmd.AddCommand(keysCmd)
}
