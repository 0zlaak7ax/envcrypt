// Package keystore manages age encryption keys for envcrypt.
package keystore

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

const defaultKeystoreFile = ".envcrypt/keys.json"

// Recipient represents a team member's public key entry.
type Recipient struct {
	Alias     string `json:"alias"`
	PublicKey string `json:"public_key"`
}

// Keystore holds the list of trusted recipients.
type Keystore struct {
	Recipients []Recipient `json:"recipients"`
	path       string
}

// Load reads the keystore from disk, returning an empty one if not found.
func Load(path string) (*Keystore, error) {
	if path == "" {
		path = defaultKeystoreFile
	}
	ks := &Keystore{path: path}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return ks, nil
	}
	if err != nil {
		return nil, err
	}
	return ks, json.Unmarshal(data, ks)
}

// Save persists the keystore to disk.
func (ks *Keystore) Save() error {
	if err := os.MkdirAll(filepath.Dir(ks.path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(ks, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(ks.path, data, 0600)
}

// Add inserts or updates a recipient by alias.
func (ks *Keystore) Add(alias, publicKey string) {
	for i, r := range ks.Recipients {
		if r.Alias == alias {
			ks.Recipients[i].PublicKey = publicKey
			return
		}
	}
	ks.Recipients = append(ks.Recipients, Recipient{Alias: alias, PublicKey: publicKey})
}

// Remove deletes a recipient by alias. Returns false if not found.
func (ks *Keystore) Remove(alias string) bool {
	for i, r := range ks.Recipients {
		if r.Alias == alias {
			ks.Recipients = append(ks.Recipients[:i], ks.Recipients[i+1:]...)
			return true
		}
	}
	return false
}

// PublicKeys returns all stored public key strings.
func (ks *Keystore) PublicKeys() []string {
	keys := make([]string, len(ks.Recipients))
	for i, r := range ks.Recipients {
		keys[i] = r.PublicKey
	}
	return keys
}
