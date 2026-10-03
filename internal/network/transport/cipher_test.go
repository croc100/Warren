package transport

import (
	"testing"
	"time"
)

// TestServerHelloEchoesMeasuredCipherSuite is H4 in the small. The relay has
// two answer paths: a tagged client is answered from local state, everyone else
// is spliced to the borrowed site. The cipher suite sits in cleartext in the
// ServerHello, so if the local path hardcodes TLS_AES_128_GCM_SHA256 while the
// borrowed site negotiates AES-256 or ChaCha20, the two paths hand different
// suites from one address — a distinguisher needing no decryption. serverAccept
// must echo whatever suite the profile measured.
func TestServerHelloEchoesMeasuredCipherSuite(t *testing.T) {
	priv, pub, err := GenerateServerIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	keys, err := newClientKeys(pub)
	if err != nil {
		t.Fatalf("client keys: %v", err)
	}

	clientRandom := randomBytes(t, 32)
	now := time.Now()
	sessionID := make([]byte, sessionIDLen)
	copy(sessionID, deriveTag(keys.authSS, clientRandom, keys.share, tagWindowIndex(now)))

	cases := []struct {
		name  string
		suite uint16
		want  uint16
	}{
		{"aes-256", 0x1302, 0x1302},
		{"chacha20", 0x1303, 0x1303},
		{"aes-128", 0x1301, 0x1301},
		{"unmeasured falls back", 0, tls13CipherSuite},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			accepted, err := serverAccept(priv, clientRandom, sessionID, keys.share, now, tc.suite)
			if err != nil {
				t.Fatalf("serverAccept: %v", err)
			}
			_, _, got, _, err := parseServerHelloParts(serverHelloBody(accepted.serverHello))
			if err != nil {
				t.Fatalf("parse ServerHello: %v", err)
			}
			if got != tc.want {
				t.Errorf("ServerHello cipher suite = 0x%04x, want 0x%04x", got, tc.want)
			}
		})
	}
}
