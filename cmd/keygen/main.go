// Command wanopt-keygen generates a fresh PSK and a server certificate, printing
// the values needed to fill in server.yaml and client.yaml.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"os"

	"wanopt/internal/tunnel"
)

func main() {
	writeCert := flag.Bool("cert", false, "also write server cert.pem/key.pem and print the pin")
	flag.Parse()

	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		fmt.Fprintln(os.Stderr, "rand:", err)
		os.Exit(1)
	}
	fmt.Println("psk:", base64.StdEncoding.EncodeToString(psk))

	if *writeCert {
		cert, pin, err := tunnel.GenerateSelfSigned()
		if err != nil {
			fmt.Fprintln(os.Stderr, "cert:", err)
			os.Exit(1)
		}
		certPEM, keyPEM, err := tunnel.EncodeCertPEM(cert)
		if err != nil {
			fmt.Fprintln(os.Stderr, "encode:", err)
			os.Exit(1)
		}
		os.WriteFile("cert.pem", certPEM, 0o600)
		os.WriteFile("key.pem", keyPEM, 0o600)
		fmt.Println("pin:", pin)
		fmt.Println("wrote cert.pem and key.pem")
	}
}
