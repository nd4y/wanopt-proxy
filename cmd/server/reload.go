package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"wanopt/internal/config"
	"wanopt/internal/safefile"
	"wanopt/internal/server"
	"wanopt/internal/tunnel"
)

func readCredentialFile(path string) ([]byte, error) { return safefile.Read(path, 1<<20) }
func watchCredentials(ctx context.Context, path string, current config.Server, srv *server.Server, log *slog.Logger, signals <-chan os.Signal) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-signals:
			next, err := config.LoadServer(path)
			if err == nil && !current.SameRuntimeSettings(*next) {
				err = errors.New("SIGHUP accepts credential changes only")
			}
			if err == nil {
				err = applyCredentials(next, srv)
			}
			if err != nil {
				log.Error("credential reload rejected", "err", err)
			} else {
				current = *next
				log.Info("credentials reloaded")
			}
		}
	}
}
func applyCredentials(c *config.Server, srv *server.Server) error {
	if c.CertFile == "" {
		return errors.New("reload requires persistent certificate")
	}
	certPEM, err := readCredentialFile(c.CertFile)
	if err != nil {
		return err
	}
	keyPEM, err := readCredentialFile(c.KeyFile)
	if err != nil {
		return err
	}
	cert, _, err := tunnel.LoadOrCreateCert(certPEM, keyPEM)
	if err != nil {
		return err
	}
	primary, err := config.DecodePSK(c.PSK)
	if err != nil {
		return err
	}
	var previous []byte
	if c.PreviousPSK != "" {
		previous, err = config.DecodePSK(c.PreviousPSK)
		if err != nil {
			return err
		}
	}
	return srv.ReloadCredentials(primary, previous, c.PreviousPSKExpires, cert)
}
