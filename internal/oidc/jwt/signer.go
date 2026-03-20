package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/miloyuans/openauthing/internal/oidc/keys"
)

type Signer struct {
	keyManager *keys.Manager
}

func NewSigner(keyManager *keys.Manager) *Signer {
	return &Signer{keyManager: keyManager}
}

func (s *Signer) Sign(claims map[string]any) (string, error) {
	if s == nil || s.keyManager == nil || s.keyManager.SigningKey() == nil {
		return "", fmt.Errorf("jwt signer is not configured")
	}

	header, err := json.Marshal(map[string]any{
		"alg": "RS256",
		"typ": "JWT",
		"kid": s.keyManager.KID(),
	})
	if err != nil {
		return "", fmt.Errorf("marshal jwt header: %w", err)
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal jwt claims: %w", err)
	}

	unsigned := encodeSegment(header) + "." + encodeSegment(payload)
	sum := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, s.keyManager.SigningKey(), crypto.SHA256, sum[:])
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}

	return strings.Join([]string{unsigned, encodeSegment(signature)}, "."), nil
}

func encodeSegment(raw []byte) string {
	return base64.RawURLEncoding.EncodeToString(raw)
}
