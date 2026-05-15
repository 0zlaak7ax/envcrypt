package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"filippo.io/age"

	"envcrypt/internal/crypto"
	"envcrypt/internal/keystore"
)

var (
	decryptOutput string
	decryptKey    string
)

var decryptCmd = &cobra.Command{
	Use:   "decrypt [file]",
	Short: "Decrypt an encrypted .env file",
	Args:  cobra.ExactArgs(1),
	RunE:  runDecrypt,
}

func init() {
	decryptCmd.Flags().StringVarP(&decryptOutput, "output", "o", "", "Output file path (default: strips .age extension)")
	decryptCmd.Flags().StringVarP(&decryptKey, "key", "k", "", "Private key to use for decryption (identity)")
	rootCmd.AddCommand(decryptCmd)
}

func runDecrypt(cmd *cobra.Command, args []string) error {
	inputFile := args[0]

	outputFile := decryptOutput
	if outputFile == "" {
		outputFile = strings.TrimSuffix(inputFile, ".age")
		if outputFile == inputFile {
			outputFile = inputFile + ".decrypted"
		}
	}

	ciphertext, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("reading encrypted file: %w", err)
	}

	var identity age.Identity
	if decryptKey != "" {
		identity, err = age.ParseX25519Identity(decryptKey)
		if err != nil {
			return fmt.Errorf("parsing provided key: %w", err)
		}
	} else {
		ks, err := keystore.Load(filepath.Join(os.Getenv("HOME"), ".envcrypt", "keys.json"))
		if err != nil {
			return fmt.Errorf("loading keystore: %w", err)
		}
		privKey := ks.GetPrivateKey()
		if privKey == "" {
			return fmt.Errorf("no private key found in keystore; use --key or run 'envcrypt keys add'")
		}
		identity, err = age.ParseX25519Identity(privKey)
		if err != nil {
			return fmt.Errorf("parsing stored key: %w", err)
		}
	}

	plaintext, err := crypto.Decrypt(ciphertext, identity)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	if err := os.WriteFile(outputFile, plaintext, 0600); err != nil {
		return fmt.Errorf("writing output file: %w", err)
	}

	fmt.Printf("Decrypted to %s\n", outputFile)
	return nil
}
