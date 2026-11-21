package analyzer

import (
	"crypto/tls"
	"testing"

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
	})

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

	result := Analyze(clienthello.Hello{})

	if len(result.Warnings) != 1 || result.Warnings[0].Code != "supported_versions_absent" {
		t.Fatalf("Warnings = %+v, want supported_versions_absent", result.Warnings)
	}
}
