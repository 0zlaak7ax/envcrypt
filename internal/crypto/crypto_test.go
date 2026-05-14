package crypto_test

import (
	"testing"

	"filippo.io/age"

	"github.com/yourorg/envcrypt/internal/crypto"
)

func generateTestKeyPair(t *testing.T) (string, string) {
	t.Helper()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}
	return identity.String(), identity.Recipient().String()
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	privKey, pubKey := generateTestKeyPair(t)

	plaintext := []byte("SECRET=hunter2\nDB_URL=postgres://localhost/mydb")

	ciphertext, err := crypto.Encrypt(plaintext, []string{pubKey})
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	if len(ciphertext) == 0 {
		t.Fatal("Encrypt() returned empty ciphertext")
	}

	decrypted, err := crypto.Decrypt(ciphertext, privKey)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypt() = %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptNoRecipients(t *testing.T) {
	_, err := crypto.Encrypt([]byte("data"), nil)
	if err == nil {
		t.Error("Encrypt() expected error for empty recipients, got nil")
	}
}

func TestEncryptInvalidRecipient(t *testing.T) {
	_, err := crypto.Encrypt([]byte("data"), []string{"not-a-valid-key"})
	if err == nil {
		t.Error("Encrypt() expected error for invalid recipient, got nil")
	}
}

func TestDecryptInvalidKey(t *testing.T) {
	_, pubKey := generateTestKeyPair(t)
	ciphertext, _ := crypto.Encrypt([]byte("secret"), []string{pubKey})

	_, err := crypto.Decrypt(ciphertext, "AGE-SECRET-KEY-INVALID")
	if err == nil {
		t.Error("Decrypt() expected error for invalid private key, got nil")
	}
}

func TestDecryptWrongKey(t *testing.T) {
	_, pubKey := generateTestKeyPair(t)
	wrongPrivKey, _ := generateTestKeyPair(t)

	ciphertext, err := crypto.Encrypt([]byte("secret"), []string{pubKey})
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	_, err = crypto.Decrypt(ciphertext, wrongPrivKey)
	if err == nil {
		t.Error("Decrypt() expected error when using wrong key, got nil")
	}
}
