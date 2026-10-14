package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestBTEAKnownVector(t *testing.T) {
	// Reference XXTEA vector: all-zero key and data, 2 words.
	cipher := BTEA{}
	data := make([]byte, 8)

	cipher.Encrypt(data)

	if got := hex.EncodeToString(data); got != "ab043705808c5d57" {
		t.Fatalf("ciphertext = %s, want ab043705808c5d57", got)
	}
}

func TestBTEARoundTrip(t *testing.T) {
	for _, rounds := range []int{0, 6} {
		cipher := BTEA{Rounds: rounds}
		copy(cipher.Key[:], "0123456789abcdef")

		plain := []byte("UE3 packet payload, 32 bytes....")
		data := append([]byte(nil), plain...)

		if !cipher.Encrypt(data) || !cipher.Decrypt(data) {
			t.Fatal("unexpected alignment rejection")
		}

		if !bytes.Equal(data, plain) {
			t.Fatalf("rounds=%d: round trip mismatch: %q", rounds, data)
		}
	}
}

func TestNewRejectsBadKey(t *testing.T) {
	if _, err := New(Config{Algorithm: "btea"}, "00ff"); err == nil {
		t.Fatal("expected error for short key")
	}
}
