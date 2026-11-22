package analyzer

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"slices"
	"time"

	"github.com/jsandas/tls-client-scanner/internal/clienthello"
	"github.com/jsandas/tls-client-scanner/internal/registry"
	"github.com/jsandas/tls-client-scanner/internal/report"
)

// Analyze transforms an observed ClientHello into a transport-independent report.
func Analyze(hello clienthello.Hello, negotiated *tls.ConnectionState) report.Report {
	knownProtocols := make([]report.Capability, 0, len(hello.SupportedVersions))
	for _, id := range hello.SupportedVersions {
		knownProtocols = append(knownProtocols, protocolCapability(id))
	}

	result := report.Report{
		SchemaVersion: report.SchemaVersion,
		ObservedAt:    time.Now().UTC(),
		ServerName:    hello.ServerName,
		RemoteAddress: hello.RemoteAddress,
		Protocols:     knownProtocols,
		CipherSuites:  cipherCapabilities(hello.CipherSuites),
		Groups:        groupCapabilities(hello.SupportedGroups),
		Signatures:    signatureCapabilities(hello.SignatureSchemes),
		NextProtocols: slices.Clone(hello.NextProtocols),
	}
	if negotiated != nil && negotiated.HandshakeComplete {
		result.Negotiated = &report.Negotiated{
			Protocol:         protocolCapability(negotiated.Version),
			CipherSuite:      cipherCapability(negotiated.CipherSuite),
			KeyExchange:      groupCapability(negotiated.CurveID),
			SignatureKeyType: signatureKeyType(negotiated),
		}
	}
	result.Warnings = warnings(hello)

	return result
}

func protocolCapability(id uint16) report.Capability {
	name, known := registry.ProtocolName(id)

	return report.Capability{
		ID:     fmt.Sprintf("0x%04x", id),
		Name:   resolvedName(name, known, id),
		Known:  known,
		GREASE: registry.IsGREASE(id),
	}
}

func cipherCapabilities(ids []uint16) []report.Capability {
	capabilities := make([]report.Capability, 0, len(ids))
	for _, id := range ids {
		capabilities = append(capabilities, cipherCapability(id))
	}

	return capabilities
}

func cipherCapability(id uint16) report.Capability {
	name, known := registry.CipherName(id)

	return report.Capability{
		ID:     fmt.Sprintf("0x%04x", id),
		Name:   resolvedName(name, known, id),
		Known:  known,
		GREASE: registry.IsGREASE(id),
	}
}

func groupCapabilities(ids []tls.CurveID) []report.Capability {
	capabilities := make([]report.Capability, 0, len(ids))
	for _, id := range ids {
		capabilities = append(capabilities, groupCapability(id))
	}

	return capabilities
}

func groupCapability(id tls.CurveID) report.Capability {
	group, known := registry.GroupMetadata(id)

	return report.Capability{
		ID:           fmt.Sprintf("0x%04x", uint16(id)),
		Name:         resolvedName(group.Name, known, uint16(id)),
		Known:        known,
		GREASE:       registry.IsGREASE(uint16(id)),
		Experimental: group.Experimental,
		PostQuantum:  group.PostQuantum,
	}
}

func signatureCapabilities(ids []tls.SignatureScheme) []report.Capability {
	capabilities := make([]report.Capability, 0, len(ids))
	for _, id := range ids {
		name, known := registry.SignatureName(id)
		capabilities = append(capabilities, report.Capability{
			ID:     fmt.Sprintf("0x%04x", uint16(id)),
			Name:   resolvedName(name, known, uint16(id)),
			Known:  known,
			GREASE: registry.IsGREASE(uint16(id)),
		})
	}

	return capabilities
}

func resolvedName(name string, known bool, id uint16) string {
	if known {
		return name
	}

	return fmt.Sprintf("unknown_0x%04x", id)
}

func warnings(hello clienthello.Hello) []report.Warning {
	warnings := make([]report.Warning, 0, 2)
	if len(hello.SupportedVersions) == 0 {
		warnings = append(warnings, report.Warning{
			Code:    "supported_versions_absent",
			Message: "The client did not advertise the supported_versions extension.",
		})
	}

	for _, id := range hello.SupportedVersions {
		switch id {
		case tls.VersionTLS10, tls.VersionTLS11:
			warnings = append(warnings, report.Warning{
				Code:    "legacy_protocol_advertised",
				Message: "The client advertised TLS 1.1 or an older protocol.",
			})

			return warnings
		}
	}

	return warnings
}

func signatureKeyType(state *tls.ConnectionState) string {
	if len(state.LocalCertificate) == 0 {
		return ""
	}

	certificate, err := x509.ParseCertificate(state.LocalCertificate[0])
	if err != nil {
		return "unknown"
	}

	switch certificate.PublicKeyAlgorithm {
	case x509.RSA:
		return "rsa"
	case x509.ECDSA:
		return "ecdsa"
	case x509.Ed25519:
		return "ed25519"
	case x509.MLDSA:
		return "mldsa"
	default:
		return "unknown"
	}
}
