package registry

import "crypto/tls"

// Group describes metadata associated with a supported_groups identifier.
type Group struct {
	Name         string
	Experimental bool
	PostQuantum  bool
}

var protocolNames = map[uint16]string{
	tls.VersionTLS10: "TLS 1.0",
	tls.VersionTLS11: "TLS 1.1",
	tls.VersionTLS12: "TLS 1.2",
	tls.VersionTLS13: "TLS 1.3",
}

var cipherNames = map[uint16]string{
	0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA",
	0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
	0x009c: "TLS_RSA_WITH_AES_128_GCM_SHA256",
	0x009d: "TLS_RSA_WITH_AES_256_GCM_SHA384",
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:   "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	tls.TLS_AES_128_GCM_SHA256:                  "TLS_AES_128_GCM_SHA256",
	tls.TLS_AES_256_GCM_SHA384:                  "TLS_AES_256_GCM_SHA384",
	tls.TLS_CHACHA20_POLY1305_SHA256:            "TLS_CHACHA20_POLY1305_SHA256",
}

var groupNames = map[tls.CurveID]Group{
	tls.CurveP256: {
		Name: "secp256r1",
	},
	tls.CurveP384: {
		Name: "secp384r1",
	},
	tls.CurveP521: {
		Name: "secp521r1",
	},
	tls.X25519: {
		Name: "X25519",
	},
	tls.X25519MLKEM768: {
		Name:        "X25519MLKEM768",
		PostQuantum: true,
	},
}

var signatureNames = map[tls.SignatureScheme]string{
	tls.PKCS1WithSHA256:        "rsa_pkcs1_sha256",
	tls.ECDSAWithP256AndSHA256: "ecdsa_secp256r1_sha256",
	tls.ECDSAWithP384AndSHA384: "ecdsa_secp384r1_sha384",
	tls.ECDSAWithP521AndSHA512: "ecdsa_secp521r1_sha512",
	tls.PSSWithSHA256:          "rsa_pss_rsae_sha256",
	tls.PSSWithSHA384:          "rsa_pss_rsae_sha384",
	tls.PSSWithSHA512:          "rsa_pss_rsae_sha512",
	tls.Ed25519:                "ed25519",
}

// ProtocolName resolves a TLS protocol version identifier.
func ProtocolName(id uint16) (string, bool) {
	name, ok := protocolNames[id]

	return name, ok
}

// CipherName resolves a TLS cipher suite identifier.
func CipherName(id uint16) (string, bool) {
	name, ok := cipherNames[id]

	return name, ok
}

// GroupMetadata resolves a TLS supported group identifier.
func GroupMetadata(id tls.CurveID) (Group, bool) {
	group, ok := groupNames[id]

	return group, ok
}

// SignatureName resolves a TLS signature scheme identifier.
func SignatureName(id tls.SignatureScheme) (string, bool) {
	name, ok := signatureNames[id]

	return name, ok
}

// IsGREASE reports whether an identifier follows the TLS GREASE reservation.
func IsGREASE(id uint16) bool {
	upper := id >> 8
	lower := id & 0x00ff

	return upper == lower && upper&0x0f == 0x0a
}
