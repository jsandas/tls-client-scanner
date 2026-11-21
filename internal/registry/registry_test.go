package registry

import (
	"testing"
)

func TestCipherNameUsesExtendedRegistry(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		id   uint16
		want string
	}{
		{
			name: "TLS 1.3 CCM",
			id:   0x1304,
			want: "TLS_AES_128_CCM_SHA256",
		},
		{
			name: "legacy export cipher",
			id:   0x0003,
			want: "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
		},
		{
			name: "draft ChaCha cipher",
			id:   0xcc13,
			want: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256_OLD",
		},
		{
			name: "fallback SCSV",
			id:   0x5600,
			want: "TLS_FALLBACK_SCSV",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, ok := CipherName(test.id)
			if !ok {
				t.Fatalf("CipherName(0x%04x) was not found", test.id)
			}

			if got != test.want {
				t.Fatalf("CipherName(0x%04x) = %q, want %q", test.id, got, test.want)
			}
		})
	}
}

func TestCipherNameRejectsUnknownIdentifier(t *testing.T) {
	t.Parallel()

	if _, ok := CipherName(0xffff); ok {
		t.Fatal("CipherName(0xffff) unexpectedly found")
	}
}
