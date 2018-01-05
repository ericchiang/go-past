package past

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"golang.org/x/crypto/ed25519"
)

func TestPAE(t *testing.T) {
	tests := []struct {
		input []string
		want  string
	}{
		{[]string{}, `\x00\x00\x00\x00\x00\x00\x00\x00`},
		{[]string{""}, `\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00`},
		{[]string{"test"}, `\x01\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00test`},
	}

	for _, test := range tests {
		got := string(pae(test.input...))

		if got != test.want {
			t.Errorf("incorrect value for %q, wanted=%q, got=%q", test.input, test.want, got)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	key, _ := hex.DecodeString("e0ea39822d1b9fa67da2c63dd51b47892f66a1e80d14a40fb3d96dc0ab839fbd")
	key2, _ := hex.DecodeString("e0ea39822d1b9fa67da2c63dd51b47892f66a1e80d14a40fb3d96dc0ab839fbe")

	tests := []struct {
		header string
		encode func(key, payload []byte) (string, error)
		decode func(key []byte, token string) ([]byte, error)
	}{
		{"v2.auth.", V2.Auth, V2.AuthVerify},
		{"v1.auth.", V1.Auth, V1.AuthVerify},
		{"v1.enc.", V1.Enc, V1.EncVerify},
	}

	for _, test := range tests {
		t.Run(test.header, func(t *testing.T) {
			payload := []byte("hi")
			token, err := test.encode(key, payload)
			if err != nil {
				t.Fatal(err)
			}

			if !strings.HasPrefix(token, test.header) {
				t.Errorf("token doesn't have expected header %s", test.header)
			}

			got, err := test.decode(key, token)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(payload, got) {
				t.Error("payload didn't round trip")
			}

			if _, err := test.decode(key2, token); err == nil {
				t.Error("invalid key didn't return error decoding token")
			}
		})
	}
}

func TestV2Sign(t *testing.T) {
	b, _ := hex.DecodeString("4c22d2a004f4b1a457c1f18cbb229dcf3a98618cf0a4f436a6076689576f9c480d738c2fc6077455dd90ea3730c17c5009978c7c03e21adda7e82bff64fb84ad")
	key := ed25519.PrivateKey(b)

	payload := []byte("hi")
	token, err := V2.Sign(key, payload)
	if err != nil {
		t.Fatal(err)
	}

	const header = "v2.sign."
	if !strings.HasPrefix(token, header) {
		t.Errorf("token doesn't have expected header %s", header)
	}

	got, err := V2.SignVerify(key.Public(), token)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(payload, got) {
		t.Error("payload didn't round trip")
	}
}
