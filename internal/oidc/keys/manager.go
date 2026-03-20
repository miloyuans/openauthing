package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"strings"

	oidcdomain "github.com/miloyuans/openauthing/internal/oidc/domain"
)

const (
	signingAlgorithm = "RS256"
	defaultKeyBits   = 2048
)

type Manager struct {
	privateKey *rsa.PrivateKey
	publicJWK  oidcdomain.JWK
}

func NewManager(signingKeyFile string, logger *slog.Logger) (*Manager, error) {
	if logger == nil {
		logger = slog.Default()
	}

	privateKey, source, err := loadOrGeneratePrivateKey(signingKeyFile)
	if err != nil {
		return nil, err
	}

	jwk, err := buildPublicJWK(privateKey)
	if err != nil {
		return nil, err
	}

	logger.Info("oidc signing key ready", "kid", jwk.KID, "algorithm", signingAlgorithm, "source", source)

	return &Manager{
		privateKey: privateKey,
		publicJWK:  jwk,
	}, nil
}

func (m *Manager) PublicJWKSet() oidcdomain.JWKSet {
	return oidcdomain.JWKSet{
		Keys: []oidcdomain.JWK{m.publicJWK},
	}
}

func (m *Manager) SigningKey() *rsa.PrivateKey {
	return m.privateKey
}

func (m *Manager) KID() string {
	return m.publicJWK.KID
}

func loadOrGeneratePrivateKey(signingKeyFile string) (*rsa.PrivateKey, string, error) {
	if strings.TrimSpace(signingKeyFile) == "" {
		privateKey, err := rsa.GenerateKey(rand.Reader, defaultKeyBits)
		if err != nil {
			return nil, "", fmt.Errorf("generate oidc rsa private key: %w", err)
		}

		return privateKey, "generated", nil
	}

	raw, err := os.ReadFile(signingKeyFile)
	if err != nil {
		return nil, "", fmt.Errorf("read oidc signing key file %q: %w", signingKeyFile, err)
	}

	privateKey, err := parsePEMPrivateKey(raw)
	if err != nil {
		return nil, "", fmt.Errorf("parse oidc signing key file %q: %w", signingKeyFile, err)
	}

	return privateKey, "file", nil
}

func parsePEMPrivateKey(raw []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("pem block not found")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return privateKey, nil
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		privateKey, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not RSA")
		}

		return privateKey, nil
	default:
		return nil, fmt.Errorf("unsupported pem block type %q", block.Type)
	}
}

func buildPublicJWK(privateKey *rsa.PrivateKey) (oidcdomain.JWK, error) {
	der, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return oidcdomain.JWK{}, fmt.Errorf("marshal public key: %w", err)
	}

	sum := sha256.Sum256(der)

	return oidcdomain.JWK{
		KTY: "RSA",
		Use: "sig",
		Alg: signingAlgorithm,
		KID: base64.RawURLEncoding.EncodeToString(sum[:]),
		N:   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes()),
		E:   encodeExponent(privateKey.PublicKey.E),
	}, nil
}

func encodeExponent(exponent int) string {
	raw := make([]byte, 4)
	binary.BigEndian.PutUint32(raw, uint32(exponent))
	raw = bytesTrimLeftZero(raw)
	if len(raw) == 0 {
		raw = []byte{0}
	}

	return base64.RawURLEncoding.EncodeToString(raw)
}

func bytesTrimLeftZero(raw []byte) []byte {
	for i, value := range raw {
		if value != 0 {
			return raw[i:]
		}
	}

	return nil
}
