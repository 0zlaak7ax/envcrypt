package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"

	"envcrypt/internal/crypto"
)

func TestRunDecryptRoundtrip(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	plaintext := []byte("DB_HOST=localhost\nDB_PORT=5432\nSECRET=supersecret\n")

	ciphertext, err := crypto.Encrypt(plaintext, []string{identity.Recipient().String()})
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}

	tmpDir := t.TempDir()
	encryptedFile := filepath.Join(tmpDir, ".env.age")
	if err := os.WriteFile(encryptedFile, ciphertext, 0644); err != nil {
		t.Fatalf("writing encrypted file: %v", err)
	}

	decryptOutput = filepath.Join(tmpDir, ".env")
	decryptKey = identity.String()
	t.Cleanup(func() {
		decryptOutput = ""
		decryptKey = ""
	})

	err = runDecrypt(decryptCmd, []string{encryptedFile})
	if err != nil {
		t.Fatalf("runDecrypt: %v", err)
	}

	got, err := os.ReadFile(decryptOutput)
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}

	if string(got) != string(plaintext) {
		t.Errorf("expected %q, got %q", plaintext, got)
	}
}

func TestRunDecryptMissingFile(t *testing.T) {
	decryptKey = "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"
	t.Cleanup(func() { decryptKey = "" })

	err := runDecrypt(decryptCmd, []string{"/nonexistent/path/.env.age"})
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestRunDecryptInvalidKey(t *testing.T) {
	tmpDir := t.TempDir()
	encryptedFile := filepath.Join(tmpDir, "test.env.age")
	if err := os.WriteFile(encryptedFile, []byte("not-valid-age-data"), 0644); err != nil {
		t.Fatalf("writing file: %v", err)
	}

	decryptKey = "not-a-valid-key"
	t.Cleanup(func() { decryptKey = "" })

	err := runDecrypt(decryptCmd, []string{encryptedFile})
	if err == nil {
		t.Error("expected error for invalid key, got nil")
	}
}
