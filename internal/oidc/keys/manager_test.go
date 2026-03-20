package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestNewManagerGeneratesRSAKeyWhenFileIsNotConfigured(t *testing.T) {
	manager, err := NewManager("", nil)
	if err != nil {
		t.Fatalf("create key manager: %v", err)
	}

	if manager.SigningKey() == nil {
		t.Fatal("expected signing key to be generated")
	}

	jwks := manager.PublicJWKSet()
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected single jwk, got %d", len(jwks.Keys))
	}

	key := jwks.Keys[0]
	if key.KTY != "RSA" || key.Alg != signingAlgorithm || key.KID == "" || key.N == "" || key.E == "" {
		t.Fatalf("unexpected jwk: %#v", key)
	}
}

func TestNewManagerLoadsRSAKeyFromPEMFile(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, defaultKeyBits)
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}

	expectedJWK, err := buildPublicJWK(privateKey)
	if err != nil {
		t.Fatalf("build public jwk: %v", err)
	}

	encoded, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal pkcs8 private key: %v", err)
	}

	tempDir := t.TempDir()
	keyPath := filepath.Join(tempDir, "oidc-signing-key.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: encoded,
	}), 0o600); err != nil {
		t.Fatalf("write private key file: %v", err)
	}

	manager, err := NewManager(keyPath, nil)
	if err != nil {
		t.Fatalf("load key manager from file: %v", err)
	}

	if manager.KID() != expectedJWK.KID {
		t.Fatalf("expected kid %q, got %q", expectedJWK.KID, manager.KID())
	}
}
