package server

import (
	"strings"
	"testing"
	"time"

	"github.com/jsandas/tls-client-scanner/internal/report"
)

// sampleReport exercises every branch of the report template.
func sampleReport() report.Report {
	return report.Report{
		SchemaVersion: "1.0.0",
		ObservedAt:    time.Date(2026, 11, 21, 14, 3, 12, 0, time.UTC),
		ServerName:    "example.com",
		Negotiated: &report.Negotiated{
			Protocol:         report.Capability{ID: "0x0304", Name: "TLS 1.3", Known: true},
			CipherSuite:      report.Capability{ID: "0x1301", Name: "TLS_AES_128_GCM_SHA256", Known: true},
			KeyExchange:      report.Capability{ID: "x25519", Name: "X25519", Known: true},
			SignatureKeyType: "rsa_pss_rsae_sha256",
		},
		Protocols: []report.Capability{
			{ID: "0x0304", Name: "TLS 1.3", Known: true},
			{ID: "0x0303", Name: "TLS 1.2", Known: true},
		},
		CipherSuites: []report.Capability{
			{ID: "0x1302", Name: "TLS_AES_256_GCM_SHA384", Known: true},
			{ID: "0x0a0a", Name: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256_OLD", Known: true, GREASE: true},
			{ID: "0x1234", Name: "unknown cipher", Known: false},
		},
		Groups: []report.Capability{
			{ID: "x25519", Name: "X25519", Known: true},
			{ID: "0x6399", Name: "X25519MLKEM768", Known: true, PostQuantum: true},
			{ID: "0xfe10", Name: "future group", Known: true, Experimental: true},
		},
		Signatures: []report.Capability{
			{ID: "0x0403", Name: "ecdsa_secp256r1_sha256", Known: true},
			{ID: "0x0601", Name: "md5_rsa", Known: false},
		},
		NextProtocols: []string{"h2", "http/1.1"},
		Warnings: []report.Warning{
			{Code: "legacy_version", Message: "Client advertises TLS 1.0."},
		},
	}
}

func TestReportTemplateRenders(t *testing.T) {
	templates, err := loadTemplates()
	if err != nil {
		t.Fatalf("load templates: %v", err)
	}

	scan := sampleReport()

	var out strings.Builder
	if err := templates.ExecuteTemplate(&out, "report.html", scan); err != nil {
		t.Fatalf("render report: %v", err)
	}

	rendered := out.String()
	for _, want := range []string{
		"TLS client capabilities",
		"example.com",
		"TLS_AES_128_GCM_SHA256",
		"rsa_pss_rsae_sha256",
		"X25519MLKEM768",
		"GREASE",
		"post-quantum",
		"experimental",
		"unknown",
		"http/1.1",
		"legacy_version",
		"/api/v1/report",
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("rendered report missing %q", want)
		}
	}
}

func TestReportTemplateWithoutNegotiatedOrWarnings(t *testing.T) {
	templates, err := loadTemplates()
	if err != nil {
		t.Fatalf("load templates: %v", err)
	}

	scan := sampleReport()
	scan.Negotiated = nil
	scan.Warnings = nil
	scan.ServerName = ""
	scan.NextProtocols = nil

	var out strings.Builder
	if err := templates.ExecuteTemplate(&out, "report.html", scan); err != nil {
		t.Fatalf("render report: %v", err)
	}

	rendered := out.String()
	if strings.Contains(rendered, "Negotiated handshake") {
		t.Error("expected negotiated section to be omitted")
	}
	if strings.Contains(rendered, "class=\"warning\"") {
		t.Error("expected warnings section to be omitted")
	}
	if !strings.Contains(rendered, "None advertised.") {
		t.Error("expected empty application protocols message")
	}
}
