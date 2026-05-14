package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/yourorg/envcrypt/internal/crypto"
	"github.com/yourorg/envcrypt/internal/keystore"
)

var (
	encryptInput  string
	encryptOutput string
	keystorePath  string
)

func init() {
	encryptCmd := &cobra.Command{
		Use:   "encrypt",
		Short: "Encrypt a .env file for all team recipients",
		RunE:  runEncrypt,
	}

	encryptCmd.Flags().StringVarP(&encryptInput, "input", "i", ".env", "Input .env file to encrypt")
	encryptCmd.Flags().StringVarP(&encryptOutput, "output", "o", ".env.age", "Output encrypted file")
	encryptCmd.Flags().StringVar(&keystorePath, "keystore", "keys.json", "Path to team keystore")

	rootCmd.AddCommand(encryptCmd)
}

func runEncrypt(cmd *cobra.Command, args []string) error {
	ks, err := keystore.Load(keystorePath)
	if err != nil {
		return fmt.Errorf("failed to load keystore: %w", err)
	}

	recipients := ks.PublicKeys()
	if len(recipients) == 0 {
		return fmt.Errorf("no recipients in keystore %q — add keys with: envcrypt keys add", keystorePath)
	}

	plaintext, err := os.ReadFile(encryptInput)
	if err != nil {
		return fmt.Errorf("failed to read input file %q: %w", encryptInput, err)
	}

	ciphertext, err := crypto.Encrypt(plaintext, recipients)
	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

	if err := os.WriteFile(encryptOutput, ciphertext, 0o644); err != nil {
		return fmt.Errorf("failed to write output file %q: %w", encryptOutput, err)
	}

	fmt.Printf("Encrypted %q → %q (%d recipients)\n", encryptInput, encryptOutput, len(recipients))
	return nil
}
