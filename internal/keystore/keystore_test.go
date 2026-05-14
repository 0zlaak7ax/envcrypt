package keystore_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/envcrypt/envcrypt/internal/keystore"
)

func tempPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "keys.json")
}

func TestLoadEmpty(t *testing.T) {
	ks, err := keystore.Load(tempPath(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ks.Recipients) != 0 {
		t.Errorf("expected empty recipients, got %d", len(ks.Recipients))
	}
}

func TestAddAndSave(t *testing.T) {
	path := tempPath(t)
	ks, _ := keystore.Load(path)
	ks.Add("alice", "age1alicepublickey")
	ks.Add("bob", "age1bobpublickey")
	if err := ks.Save(); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	loaded, err := keystore.Load(path)
	if err != nil {
		t.Fatalf("reload failed: %v", err)
	}
	if len(loaded.Recipients) != 2 {
		t.Errorf("expected 2 recipients, got %d", len(loaded.Recipients))
	}
}

func TestAddUpdatesExisting(t *testing.T) {
	path := tempPath(t)
	ks, _ := keystore.Load(path)
	ks.Add("alice", "age1old")
	ks.Add("alice", "age1new")
	if len(ks.Recipients) != 1 {
		t.Errorf("expected 1 recipient after update, got %d", len(ks.Recipients))
	}
	if ks.Recipients[0].PublicKey != "age1new" {
		t.Errorf("expected updated key, got %s", ks.Recipients[0].PublicKey)
	}
}

func TestRemove(t *testing.T) {
	path := tempPath(t)
	ks, _ := keystore.Load(path)
	ks.Add("alice", "age1alice")
	if !ks.Remove("alice") {
		t.Error("expected Remove to return true")
	}
	if ks.Remove("ghost") {
		t.Error("expected Remove to return false for unknown alias")
	}
	if len(ks.Recipients) != 0 {
		t.Errorf("expected 0 recipients, got %d", len(ks.Recipients))
	}
}

func TestPublicKeys(t *testing.T) {
	path := tempPath(t)
	ks, _ := keystore.Load(path)
	ks.Add("alice", "age1alice")
	ks.Add("bob", "age1bob")
	keys := ks.PublicKeys()
	if len(keys) != 2 {
		t.Errorf("expected 2 keys, got %d", len(keys))
	}
}

func TestSaveCreatesDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "dir")
	path := filepath.Join(dir, "keys.json")
	ks, _ := keystore.Load(path)
	ks.Add("alice", "age1alice")
	if err := ks.Save(); err != nil {
		t.Fatalf("expected dir creation, got error: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("file not created: %v", err)
	}
}
