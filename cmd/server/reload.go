package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"wanopt/internal/config"
	"wanopt/internal/server"
	"wanopt/internal/tunnel"
)

func readCredentialFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > 1<<20 {
		return nil, errors.New("credential file must be a regular file up to 1 MiB")
	}
	b, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if len(b) > 1<<20 {
		return nil, errors.New("credential file too large")
	}
	return b, err
}
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
