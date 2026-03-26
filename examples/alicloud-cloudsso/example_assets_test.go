package alicloudcloudsso_test

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

func TestEnvExampleContainsRequiredCloudSSOFields(t *testing.T) {
	raw := mustRead(t, "alicloud-cloudsso.env.example")

	for _, expected := range []string{
		"ALICLOUD_CLOUDSSO_SAML_ENTITY_ID=",
		"ALICLOUD_CLOUDSSO_SAML_ACS_URL=",
		"ALICLOUD_CLOUDSSO_SCIM_ENDPOINT=",
		"ALICLOUD_CLOUDSSO_SCIM_TOKEN=",
		"DEMO_USERNAME=cloudsso.demo@example.test",
		"GROUP_CODE=alicloud-platform",
	} {
		if !strings.Contains(raw, expected) {
			t.Fatalf("expected %q in env example", expected)
		}
	}
}

func TestSeedContainsSAMLAndSCIMApplications(t *testing.T) {
	raw := mustRead(t, "seed/alicloud_cloudsso_seed.sql")

	for _, expected := range []string{
		"'saml-sp'",
		"'scim-target'",
		"INSERT INTO saml_service_providers",
		"INSERT INTO groups",
		"INSERT INTO users",
		"\"display_name\"",
	} {
		if !strings.Contains(raw, expected) {
			t.Fatalf("expected %q in seed sql", expected)
		}
	}
}

func TestExampleReadmeMentionsRequiredIntegrationFields(t *testing.T) {
	raw := mustRead(t, "README.md")

	for _, expected := range []string{
		"外部 IdP",
		"Entity ID",
		"Logon URL",
		"Certificate",
		"SCIM",
		"userName",
		"displayName",
		"emails",
		"active",
		"groups",
		"metadata 错误",
		"证书错误",
		"SCIM token 配置错误",
		"用户组同步不完整",
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
