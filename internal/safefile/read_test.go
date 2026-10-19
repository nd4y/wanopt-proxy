package safefile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRegularFileSizeAndType(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(p, []byte("abc"), 0600); err != nil {
		t.Fatal(err)
	}
	if b, err := Read(p, 3); err != nil || string(b) != "abc" {
		t.Fatal(b, err)
	}
	if _, err := Read(p, 2); err == nil {
		t.Fatal("oversized file accepted")
	}
	if _, err := Read(filepath.Dir(p), 100); err == nil {
		t.Fatal("directory accepted")
	}
}
