package clienthello

import (
	"crypto/tls"
	"slices"
)

const maxObservedValues = 256

// Hello is the portion of a TLS ClientHello that crypto/tls exposes.
type Hello struct {
	SupportedVersions []uint16
	CipherSuites      []uint16
	SupportedGroups   []tls.CurveID
	SignatureSchemes  []tls.SignatureScheme
	NextProtocols     []string
	ServerName        string
	RemoteAddress     string
}

// FromTLS converts crypto/tls ClientHelloInfo into an immutable observation.
func FromTLS(info *tls.ClientHelloInfo) Hello {
	hello := Hello{
		SupportedVersions: copyIDs(info.SupportedVersions),
		CipherSuites:      copyIDs(info.CipherSuites),
		SignatureSchemes:  append([]tls.SignatureScheme(nil), info.SignatureSchemes...),
		NextProtocols:     append([]string(nil), info.SupportedProtos...),
		ServerName:        info.ServerName,
	}

	hello.SupportedGroups = append([]tls.CurveID(nil), info.SupportedCurves...)

	if info.Conn != nil {
		hello.RemoteAddress = info.Conn.RemoteAddr().String()
	}

	return limit(hello)
}

func copyIDs(values []uint16) []uint16 {
	return slices.Clone(values)
}

func limit(hello Hello) Hello {
	hello.SupportedVersions = truncate(hello.SupportedVersions)
	hello.CipherSuites = truncate(hello.CipherSuites)
	hello.SupportedGroups = truncate(hello.SupportedGroups)
	hello.SignatureSchemes = truncate(hello.SignatureSchemes)
	hello.NextProtocols = truncate(hello.NextProtocols)

	return hello
}

func truncate[T any](values []T) []T {
	if len(values) <= maxObservedValues {
		return values
	}

	return values[:maxObservedValues]
}
