package clienthello

import (
	"crypto/tls"
	"testing"
)

func TestFromTLSCopiesClientHelloValues(t *testing.T) {
	t.Parallel()

	versions := []uint16{tls.VersionTLS13, tls.VersionTLS12}
	info := &tls.ClientHelloInfo{
		SupportedVersions: versions,
		CipherSuites:      []uint16{tls.TLS_AES_128_GCM_SHA256},
		SupportedCurves:   []tls.CurveID{tls.X25519MLKEM768},
		SignatureSchemes:  []tls.SignatureScheme{tls.PSSWithSHA256},
		SupportedProtos:   []string{"h2", "http/1.1"},
		ServerName:        "example.test",
	}

	hello := FromTLS(info)
	versions[0] = tls.VersionTLS10

	if got := hello.SupportedVersions[0]; got != tls.VersionTLS13 {
		t.Fatalf("SupportedVersions[0] = 0x%x, want 0x%x", got, tls.VersionTLS13)
	}

	if hello.ServerName != "example.test" {
		t.Fatalf("ServerName = %q, want example.test", hello.ServerName)
	}
}
