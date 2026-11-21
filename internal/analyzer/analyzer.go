package analyzer

import (
	"crypto/tls"
	"fmt"
	"slices"
	"time"

	"github.com/jsandas/tls-client-scanner/internal/clienthello"
	"github.com/jsandas/tls-client-scanner/internal/registry"
	"github.com/jsandas/tls-client-scanner/internal/report"
)

// Analyze transforms an observed ClientHello into a transport-independent report.
func Analyze(hello clienthello.Hello) report.Report {
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
		name, known := registry.CipherName(id)
		capabilities = append(capabilities, report.Capability{
			ID:     fmt.Sprintf("0x%04x", id),
			Name:   resolvedName(name, known, id),
			Known:  known,
			GREASE: registry.IsGREASE(id),
		})
	}

	return capabilities
}

func groupCapabilities(ids []tls.CurveID) []report.Capability {
	capabilities := make([]report.Capability, 0, len(ids))
	for _, id := range ids {
		group, known := registry.GroupMetadata(id)
		capabilities = append(capabilities, report.Capability{
			ID:           fmt.Sprintf("0x%04x", uint16(id)),
			Name:         resolvedName(group.Name, known, uint16(id)),
			Known:        known,
			GREASE:       registry.IsGREASE(uint16(id)),
			Experimental: group.Experimental,
			PostQuantum:  group.PostQuantum,
		})
	}

	return capabilities
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
