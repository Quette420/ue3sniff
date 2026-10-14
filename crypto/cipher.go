package crypto

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Cipher decrypts a captured UDP payload in place. It returns false when
// the payload cannot be decrypted (for example, wrong block alignment).
type Cipher interface {
	Decrypt(data []byte) bool
}

// Config selects a packet cipher. It is usually part of a game profile.
type Config struct {
	// Algorithm is "none" or "btea".
	Algorithm string `json:"algorithm"`

	// Rounds overrides the BTEA round count. 0 uses the standard
	// XXTEA schedule (6 + 52/n).
	Rounds int `json:"rounds,omitempty"`
}

// New builds the cipher described by config. keyHex may be empty, in which
// case nil is returned and traffic is treated as plaintext.
func New(config Config, keyHex string) (Cipher, error) {
	algorithm := strings.ToLower(config.Algorithm)

	if algorithm == "" || algorithm == "none" {
		if keyHex != "" {
			return nil, fmt.Errorf("profile has no cipher, but -key was given")
		}

		return nil, nil
	}

	if keyHex == "" {
		return nil, nil
	}

	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid key: %w", err)
	}

	switch algorithm {
	case "btea", "xxtea":
		if len(key) != 16 {
			return nil, fmt.Errorf(
				"BTEA key must be exactly 16 bytes (32 hex chars), got %d",
				len(key),
			)
		}

		cipher := BTEA{Rounds: config.Rounds}
		copy(cipher.Key[:], key)

		return cipher, nil

	default:
		return nil, fmt.Errorf("unknown cipher %q", config.Algorithm)
	}
}
