package sessionid

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

const rawSIDLength = 32

func Generate() (string, error) {
	raw := make([]byte, rawSIDLength)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("read random sid: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func Hash(secret, sid string) (string, error) {
	trimmedSecret := strings.TrimSpace(secret)
	trimmedSID := strings.TrimSpace(sid)
	if trimmedSecret == "" || trimmedSID == "" {
		return "", fmt.Errorf("session secret and sid are required")
	}

	mac := hmac.New(sha256.New, []byte(trimmedSecret))
	if _, err := mac.Write([]byte(trimmedSID)); err != nil {
		return "", fmt.Errorf("hash sid: %w", err)
	}

	return hex.EncodeToString(mac.Sum(nil)), nil
}
