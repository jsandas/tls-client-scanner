package app

import (
	"context"
	"fmt"

	"github.com/jsandas/tls-client-scanner/internal/config"
	"github.com/jsandas/tls-client-scanner/internal/server"
)

// Run starts the application and blocks until ctx is canceled or serving fails.
func Run(ctx context.Context, cfg config.Config) error {
	tlsConfig, err := cfg.TLSConfig()
	if err != nil {
		return err
	}

	application, err := server.New(cfg.Address, tlsConfig)
	if err != nil {
		return err
	}

	if err := application.Serve(ctx); err != nil {
		return fmt.Errorf("application server: %w", err)
	}

	return nil
}
