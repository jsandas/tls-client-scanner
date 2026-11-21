package config

import (
	"crypto/tls"
	"errors"
	"fmt"
	"os"
)

const DefaultAddress = "127.0.0.1:8443"

// Config contains runtime server settings.
type Config struct {
	Address  string
	CertFile string
	KeyFile  string
}

// TLSConfig loads the server certificate and applies safe protocol defaults.
func (c Config) TLSConfig() (*tls.Config, error) {
	if c.CertFile == "" || c.KeyFile == "" {
		return nil, errors.New("both certificate and key files are required")
	}

	if _, err := os.Stat(c.CertFile); err != nil {
		return nil, fmt.Errorf("stat certificate: %w", err)
	}

	if _, err := os.Stat(c.KeyFile); err != nil {
		return nil, fmt.Errorf("stat private key: %w", err)
	}

	certificate, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS key pair: %w", err)
	}

	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{"h2", "http/1.1"},
	}, nil
}
