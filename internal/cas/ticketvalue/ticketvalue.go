package ticketvalue

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

const rawValueLength = 32

func Generate(prefix string) (string, error) {
	trimmedPrefix := strings.TrimSpace(prefix)
	if trimmedPrefix == "" {
		return "", fmt.Errorf("ticket prefix is required")
	}

	raw := make([]byte, rawValueLength)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("read random ticket value: %w", err)
	}

	return trimmedPrefix + "-" + base64.RawURLEncoding.EncodeToString(raw), nil
}

func Hash(secret, rawValue string) (string, error) {
	trimmedSecret := strings.TrimSpace(secret)
	trimmedValue := strings.TrimSpace(rawValue)
	if trimmedSecret == "" || trimmedValue == "" {
		return "", fmt.Errorf("ticket secret and raw value are required")
	}

	mac := hmac.New(sha256.New, []byte(trimmedSecret))
	if _, err := mac.Write([]byte(trimmedValue)); err != nil {
		return "", fmt.Errorf("hash ticket value: %w", err)
	}

	return hex.EncodeToString(mac.Sum(nil)), nil
}
