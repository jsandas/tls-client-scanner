package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/jsandas/tls-client-scanner/internal/app"
	"github.com/jsandas/tls-client-scanner/internal/config"
)

func main() {
	address := flag.String("address", config.DefaultAddress, "HTTPS listen address")
	certFile := flag.String("cert", "", "TLS certificate PEM file")
	keyFile := flag.String("key", "", "TLS private-key PEM file")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err := app.Run(ctx, config.Config{
		Address:  *address,
		CertFile: *certFile,
		KeyFile:  *keyFile,
	})
	if err != nil {
		log.Printf("tls-client-scanner failed: %v", err)
		os.Exit(1)
	}
}
