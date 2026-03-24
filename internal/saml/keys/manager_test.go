package keys

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewManagerGeneratesDevelopmentCertificateWhenFilesAreNotConfigured(t *testing.T) {
	manager, err := NewManager("https://iam.example.test/saml/idp/metadata", "", "", nil)
	if err != nil {
		t.Fatalf("create key manager: %v", err)
	}

	if manager.Certificate() == nil || manager.PrivateKey() == nil {
		t.Fatal("expected generated certificate and private key")
	}

	if manager.MetadataCertificate() == "" {
		t.Fatal("expected metadata certificate content")
	}
}

func TestNewManagerLoadsCertificateAndPrivateKeyFromFiles(t *testing.T) {
	certificate, privateKey, err := generateDevelopmentCertificate("https://iam.example.test/saml/idp/metadata")
	if err != nil {
		t.Fatalf("generate development certificate: %v", err)
	}

	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}

	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "saml-idp-cert.pem")
	keyPath := filepath.Join(tempDir, "saml-idp-key.pem")

	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}), 0o600); err != nil {
		t.Fatalf("write certificate: %v", err)
	}

	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER}), 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}

	manager, err := NewManager("https://iam.example.test/saml/idp/metadata", certPath, keyPath, nil)
	if err != nil {
		t.Fatalf("load key manager: %v", err)
	}

	if manager.Certificate().Subject.CommonName == "" {
		t.Fatal("expected certificate subject")
	}

	if !strings.Contains(manager.MetadataCertificate(), "MII") {
		t.Fatalf("expected base64 certificate output, got %q", manager.MetadataCertificate())
	}
}
