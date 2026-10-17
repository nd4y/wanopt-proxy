// Command wanopt-keygen generates a PSK and optionally a persistent certificate.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"wanopt/internal/tunnel"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("wanopt-keygen", flag.ContinueOnError)
	writeCert := flags.Bool("cert", false, "write a persistent cert.pem/key.pem pair (never overwrite)")
	dir := flags.String("out", ".", "existing output directory for certificate and private key")
	if err := flags.Parse(args); err != nil {
		return err
	}
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		return err
	}
	if *writeCert {
		cert, pin, err := tunnel.GenerateSelfSigned()
		if err != nil {
			return err
		}
		certPEM, keyPEM, err := tunnel.EncodeCertPEM(cert)
		if err != nil {
			return err
		}
		keyPath, certPath := filepath.Join(*dir, "key.pem"), filepath.Join(*dir, "cert.pem")
		if err := writeExclusive(keyPath, keyPEM); err != nil {
			return err
		}
		if err := writeExclusive(certPath, certPEM); err != nil {
			os.Remove(keyPath)
			return err
		}
		fmt.Fprintln(out, "pin:", pin)
		fmt.Fprintln(out, "wrote", certPath, "and", keyPath)
	}
	_, err := fmt.Fprintln(out, "psk:", base64.StdEncoding.EncodeToString(psk))
	return err
}
func writeExclusive(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	n, err := f.Write(data)
	closeErr := f.Close()
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(path)
	}
	return err
}
