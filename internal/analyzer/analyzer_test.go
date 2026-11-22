package analyzer

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/jsandas/tls-client-scanner/internal/clienthello"
	"github.com/jsandas/tls-client-scanner/internal/report"
)

func TestAnalyzeReportsAdvertisedCapabilities(t *testing.T) {
	t.Parallel()

	result := Analyze(clienthello.Hello{
		SupportedVersions: []uint16{tls.VersionTLS13, 0x7a7a},
		CipherSuites:      []uint16{tls.TLS_AES_128_GCM_SHA256},
		SupportedGroups:   []tls.CurveID{tls.X25519MLKEM768},
		SignatureSchemes:  []tls.SignatureScheme{tls.PSSWithSHA256},
		NextProtocols:     []string{"h2"},
	}, nil)

	if result.SchemaVersion != report.SchemaVersion {
		t.Fatalf("SchemaVersion = %q, want %q", result.SchemaVersion, report.SchemaVersion)
	}

	if result.Groups[0].Name != "X25519MLKEM768" || !result.Groups[0].PostQuantum {
		t.Fatalf("group = %+v, want known post-quantum group", result.Groups[0])
	}

	if !result.Protocols[1].GREASE {
		t.Fatal("GREASE version was not marked")
	}
}

func TestAnalyzeWarnsWhenSupportedVersionsIsAbsent(t *testing.T) {
	t.Parallel()

	result := Analyze(clienthello.Hello{}, nil)

	if len(result.Warnings) != 1 || result.Warnings[0].Code != "supported_versions_absent" {
		t.Fatalf("Warnings = %+v, want supported_versions_absent", result.Warnings)
	}
}

func TestAnalyzeReportsNegotiatedHandshake(t *testing.T) {
	t.Parallel()

	state := &tls.ConnectionState{
		HandshakeComplete: true,
		Version:           tls.VersionTLS13,
		CipherSuite:       tls.TLS_AES_128_GCM_SHA256,
		CurveID:           tls.X25519,
	}
	result := Analyze(clienthello.Hello{}, state)

	if result.Negotiated == nil {
		t.Fatal("Negotiated = nil, want negotiated handshake")
	}

	if result.Negotiated.Protocol.Name != "TLS 1.3" {
		t.Fatalf("Negotiated.Protocol = %+v, want TLS 1.3", result.Negotiated.Protocol)
	}
	if result.Negotiated.CipherSuite.Name != "TLS_AES_128_GCM_SHA256" {
		t.Fatalf("Negotiated.CipherSuite = %+v, want TLS_AES_128_GCM_SHA256", result.Negotiated.CipherSuite)
	}
	if result.Negotiated.KeyExchange.Name != "X25519" {
		t.Fatalf("Negotiated.KeyExchange = %+v, want X25519", result.Negotiated.KeyExchange)
	}
	if result.Negotiated.SignatureKeyType != "" {
		t.Fatalf("Negotiated.SignatureKeyType = %q, want empty without local certificate", result.Negotiated.SignatureKeyType)
	}
}

func TestAnalyzeReportsNegotiatedSignatureKeyType(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "scanner.test",
		},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}

	state := &tls.ConnectionState{
		HandshakeComplete: true,
		Version:           tls.VersionTLS13,
		CipherSuite:       tls.TLS_AES_128_GCM_SHA256,
		CurveID:           tls.X25519,
		LocalCertificate:  [][]byte{certificateDER},
	}
	result := Analyze(clienthello.Hello{}, state)

	if result.Negotiated == nil {
		t.Fatal("Negotiated = nil, want negotiated handshake")
	}
	if result.Negotiated.SignatureKeyType != "rsa" {
		t.Fatalf("Negotiated.SignatureKeyType = %q, want rsa", result.Negotiated.SignatureKeyType)
	}
}
