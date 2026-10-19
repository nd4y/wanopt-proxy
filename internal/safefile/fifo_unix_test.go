//go:build unix

package safefile

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestFIFORejectedWithoutWaitingForWriter(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(p, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := Read(p, 100); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("configuration FIFO blocked reload")
	}
}
