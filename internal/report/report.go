package report

import "time"

const SchemaVersion = "1.0.0"

// Report is the versioned, transport-independent client capability report.
type Report struct {
	SchemaVersion string       `json:"schema_version"`
	ObservedAt    time.Time    `json:"observed_at"`
	ServerName    string       `json:"server_name,omitempty"`
	RemoteAddress string       `json:"remote_address,omitempty"`
	Negotiated    *Negotiated  `json:"negotiated,omitempty"`
	Protocols     []Capability `json:"protocols"`
	CipherSuites  []Capability `json:"cipher_suites"`
	Groups        []Capability `json:"groups"`
	Signatures    []Capability `json:"signatures"`
	NextProtocols []string     `json:"next_protocols"`
	Warnings      []Warning    `json:"warnings"`
}

// Negotiated describes the final TLS handshake parameters selected by the server.
type Negotiated struct {
	Protocol         Capability `json:"protocol"`
	CipherSuite      Capability `json:"cipher_suite"`
	KeyExchange      Capability `json:"key_exchange"`
	SignatureKeyType string     `json:"signature_key_type,omitempty"`
}

// Capability describes a value advertised by a TLS client.
type Capability struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Known        bool   `json:"known"`
	GREASE       bool   `json:"grease,omitempty"`
	Experimental bool   `json:"experimental,omitempty"`
	PostQuantum  bool   `json:"post_quantum,omitempty"`
}

// Warning records an ambiguity or notable condition in the observation.
type Warning struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
