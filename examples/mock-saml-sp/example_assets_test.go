package main

import (
	"os"
	"strings"
	"testing"
)

func TestComposeIncludesMockSPRuntime(t *testing.T) {
	raw := mustReadAsset(t, "docker-compose.yml")

	for _, expected := range []string{"openauthing:", "mock-saml-sp:", "postgres:", "redis:"} {
		if !strings.Contains(raw, expected) {
			t.Fatalf("expected %q in docker-compose example", expected)
		}
	}
}

func TestEnvExampleContainsRequiredFields(t *testing.T) {
	raw := mustReadAsset(t, "mock-saml-sp.env.example")

	for _, expected := range []string{
		"MOCK_SAML_SP_BASE_URL=",
		"MOCK_SAML_SP_ENTITY_ID=",
		"MOCK_SAML_SP_ACS_URL=",
		"MOCK_SAML_SP_IDP_SSO_URL=",
		"MOCK_SAML_SP_IDP_METADATA_URL=",
		"DEMO_USERNAME=mocksaml.demo@example.test",
		"GROUP_CODE=mock-saml-platform",
	} {
		if !strings.Contains(raw, expected) {
			t.Fatalf("expected %q in env example", expected)
		}
	}
}

func TestSeedContainsSAMLApplicationAndDemoUser(t *testing.T) {
	raw := mustReadAsset(t, "seed/mock_saml_sp_seed.sql")

	for _, expected := range []string{
		"'saml-sp'",
		"INSERT INTO saml_service_providers",
		"INSERT INTO groups",
		"INSERT INTO users",
		"mock-saml-sp",
	} {
		if !strings.Contains(raw, expected) {
			t.Fatalf("expected %q in seed sql", expected)
		}
	}
}

func TestReadmeMentionsRequiredTroubleshootingAndFlow(t *testing.T) {
	raw := mustReadAsset(t, "README.md")

	for _, expected := range []string{
		"AuthnRequest",
		"ACS POST",
		"Assertion",
		"Signature",
		"RelayState",
		"属性映射",
		"ACS URL does not match",
		"unknown service provider issuer",
		"signature validation",
	} {
		if !strings.Contains(raw, expected) {
			t.Fatalf("expected %q in README", expected)
		}
	}
}

func mustReadAsset(t *testing.T, path string) string {
	t.Helper()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	return string(raw)
}
