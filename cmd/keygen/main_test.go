package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestKeygenDoesNotOverwrite(t *testing.T) {
	dir := t.TempDir()
	if err := run([]string{"-cert", "-out", dir}, io.Discard); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(dir, "key.pem"))
	if err := run([]string{"-cert", "-out", dir}, io.Discard); err == nil {
		t.Fatal("overwrote key")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "key.pem"))
	if !bytes.Equal(before, after) {
		t.Fatal("key changed")
	}
}
func TestKeygenRollsBackNewKeyOnCertificateConflict(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "cert.pem"), []byte("existing"), 0600)
	if err := run([]string{"-cert", "-out", dir}, io.Discard); err == nil {
		t.Fatal("accepted existing certificate")
	}
	if _, err := os.Stat(filepath.Join(dir, "key.pem")); !os.IsNotExist(err) {
		t.Fatal("partial key retained")
	}
	b, _ := os.ReadFile(filepath.Join(dir, "cert.pem"))
	if string(b) != "existing" {
		t.Fatal("certificate changed")
	}
}
