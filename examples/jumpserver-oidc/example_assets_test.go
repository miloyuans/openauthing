package jumpserveroidc_test

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

func TestJumpServerConfigTemplateContainsRequiredOIDCFields(t *testing.T) {
	raw := mustRead(t, "jumpserver-config.txt.example")

	for _, expected := range []string{
		"AUTH_OPENID_CLIENT_ID=jumpserver-local",
		"AUTH_OPENID_CLIENT_SECRET=jumpserver-local-secret",
		"AUTH_OPENID_PROVIDER_AUTHORIZATION_ENDPOINT=http://host.docker.internal:8080/oauth2/authorize",
		"AUTH_OPENID_PROVIDER_TOKEN_ENDPOINT=http://host.docker.internal:8080/oauth2/token",
		"AUTH_OPENID_PROVIDER_USERINFO_ENDPOINT=http://host.docker.internal:8080/oauth2/userinfo",
		"AUTH_OPENID_SCOPES=openid profile email offline_access",
		"callback=http://localhost:8082/core/auth/openid/callback/",
	} {
		if !strings.Contains(raw, expected) {
			t.Fatalf("expected %q in JumpServer config example", expected)
		}
	}
}

func TestExampleReadmeMentionsRequiredIntegrationFields(t *testing.T) {
	raw := mustRead(t, "README.md")

	for _, expected := range []string{
		"issuer",
		"client_id",
		"client_secret",
		"authorization endpoint",
		"token endpoint",
		"userinfo endpoint",
		"scopes",
		"callback",
		"preferred_username",
		"email",
		"name",
		"groups",
		"自动创建或更新用户",
	} {
		if !strings.Contains(raw, expected) {
			t.Fatalf("expected %q in JumpServer example README", expected)
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
