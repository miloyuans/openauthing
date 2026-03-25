package awsiamidentitycenter_test

import (
	"os"
	"strings"
	"testing"
)

func TestComposeIncludesOpenauthingRuntime(t *testing.T) {
	raw := mustRead(t, "docker-compose.yml")

	for _, expected := range []string{"openauthing:", "postgres:", "redis:"} {
		if !strings.Contains(raw, expected) {
			t.Fatalf("expected %q in docker-compose example", expected)
		}
	}
}

func TestEnvExampleContainsRequiredAWSFields(t *testing.T) {
	raw := mustRead(t, "aws-iam-identity-center.env.example")

	for _, expected := range []string{
		"AWS_IIC_SAML_ENTITY_ID=",
		"AWS_IIC_SAML_ACS_URL=",
		"AWS_IIC_ACCESS_PORTAL_URL=",
		"AWS_IIC_SCIM_ENDPOINT=",
		"AWS_IIC_SCIM_ACCESS_TOKEN=",
		"DEMO_USERNAME=aws.demo@example.test",
		"GROUP_CODE=aws-engineering",
	} {
		if !strings.Contains(raw, expected) {
			t.Fatalf("expected %q in env example", expected)
		}
	}
}

func TestSeedContainsSAMLAndSCIMApplications(t *testing.T) {
	raw := mustRead(t, "seed/aws_iam_identity_center_seed.sql")

	for _, expected := range []string{
		"'saml-sp'",
		"'scim-target'",
		"INSERT INTO saml_service_providers",
		"INSERT INTO groups",
		"INSERT INTO users",
	} {
		if !strings.Contains(raw, expected) {
			t.Fatalf("expected %q in seed sql", expected)
		}
	}
}

func TestExampleReadmeMentionsRequiredIntegrationFields(t *testing.T) {
	raw := mustRead(t, "README.md")

	for _, expected := range []string{
		"外部 SAML IdP",
		"entityID",
		"ACS URL",
		"SCIM",
		"NameID",
		"userName",
		"displayName",
		"emails",
		"active",
		"groups",
		"permission set",
		"SAML issuer",
		"ACS 配置错误",
		"用户未 provision",
	} {
		if !strings.Contains(raw, expected) {
			t.Fatalf("expected %q in example README", expected)
		}
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	return string(raw)
}
