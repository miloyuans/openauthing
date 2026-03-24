package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net/url"
	"os"
	"strings"
	"time"
)

const defaultRSAKeyBits = 2048

type Manager struct {
	certificate *x509.Certificate
	privateKey  *rsa.PrivateKey
}

func NewManager(entityID, certificateFile, privateKeyFile string, logger *slog.Logger) (*Manager, error) {
	if logger == nil {
		logger = slog.Default()
	}

	certificate, privateKey, source, err := loadOrGenerate(entityID, certificateFile, privateKeyFile)
	if err != nil {
		return nil, err
	}

	logger.Info("saml signing certificate ready", "source", source, "subject", certificate.Subject.CommonName, "not_after", certificate.NotAfter.UTC())

	return &Manager{
		certificate: certificate,
		privateKey:  privateKey,
	}, nil
}

func (m *Manager) Certificate() *x509.Certificate {
	return m.certificate
}

func (m *Manager) PrivateKey() *rsa.PrivateKey {
	return m.privateKey
}

func (m *Manager) MetadataCertificate() string {
	return base64.StdEncoding.EncodeToString(m.certificate.Raw)
}

func loadOrGenerate(entityID, certificateFile, privateKeyFile string) (*x509.Certificate, *rsa.PrivateKey, string, error) {
	certificateFile = strings.TrimSpace(certificateFile)
	privateKeyFile = strings.TrimSpace(privateKeyFile)
	if certificateFile == "" && privateKeyFile == "" {
		certificate, privateKey, err := generateDevelopmentCertificate(entityID)
		if err != nil {
			return nil, nil, "", err
		}

		return certificate, privateKey, "generated", nil
	}

	certificatePEM, err := os.ReadFile(certificateFile)
	if err != nil {
		return nil, nil, "", fmt.Errorf("read saml certificate file %q: %w", certificateFile, err)
	}

	privateKeyPEM, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return nil, nil, "", fmt.Errorf("read saml private key file %q: %w", privateKeyFile, err)
	}

	certificate, err := parseCertificate(certificatePEM)
	if err != nil {
		return nil, nil, "", fmt.Errorf("parse saml certificate file %q: %w", certificateFile, err)
	}

	privateKey, err := parsePrivateKey(privateKeyPEM)
	if err != nil {
		return nil, nil, "", fmt.Errorf("parse saml private key file %q: %w", privateKeyFile, err)
	}

	if err := validateKeyPair(certificate, privateKey); err != nil {
		return nil, nil, "", fmt.Errorf("validate saml certificate and private key: %w", err)
	}

	return certificate, privateKey, "file", nil
}

func parseCertificate(raw []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("certificate pem block not found")
	}

	return x509.ParseCertificate(block.Bytes)
}

func parsePrivateKey(raw []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("private key pem block not found")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
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
		return nil, fmt.Errorf("unsupported private key pem block type %q", block.Type)
	}
}

func generateDevelopmentCertificate(entityID string) (*x509.Certificate, *rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, defaultRSAKeyBits)
	if err != nil {
		return nil, nil, fmt.Errorf("generate saml rsa private key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("generate saml certificate serial number: %w", err)
	}

	subjectCN := "openauthing SAML IdP"
	dnsNames := []string{}
	if parsed, parseErr := url.Parse(strings.TrimSpace(entityID)); parseErr == nil && parsed.Hostname() != "" {
		subjectCN = parsed.Hostname()
		dnsNames = append(dnsNames, parsed.Hostname())
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   subjectCN,
			Organization: []string{"openauthing"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour).UTC(),
		NotAfter:              time.Now().AddDate(5, 0, 0).UTC(),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              dnsNames,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create saml self-signed certificate: %w", err)
	}

	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parse generated saml certificate: %w", err)
	}

	return certificate, privateKey, nil
}

func validateKeyPair(certificate *x509.Certificate, privateKey *rsa.PrivateKey) error {
	publicKey, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("certificate public key is not RSA")
	}

	if publicKey.N.Cmp(privateKey.PublicKey.N) != 0 || publicKey.E != privateKey.PublicKey.E {
		return fmt.Errorf("certificate and private key do not match")
	}

	return nil
}
