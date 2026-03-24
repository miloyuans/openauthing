package jenkinsoidc_test

import (
	"os"
	"strings"
	"testing"
)

func TestComposeIncludesOpenauthingAndJenkins(t *testing.T) {
	raw := mustRead(t, "docker-compose.yml")

	for _, expected := range []string{"openauthing:", "jenkins:", "postgres:", "redis:"} {
		if !strings.Contains(raw, expected) {
			t.Fatalf("expected %q in docker-compose example", expected)
		}
	}
}

func TestJenkinsPluginsIncludeOIDCAuth(t *testing.T) {
	raw := mustRead(t, "jenkins/plugins.txt")

	if !strings.Contains(raw, "oic-auth") {
		t.Fatal("expected Jenkins OIDC plugin in plugins.txt")
	}
}

func TestExampleReadmeMentionsRequiredOIDCFields(t *testing.T) {
	raw := mustRead(t, "README.md")

	for _, expected := range []string{
		"issuer",
		"Client ID",
		"Client Secret",
		"securityRealm/finishLogin",
		"OicLogout",
		"openid profile email",
		"preferred_username",
		"email",
		"groups",
	} {
		if !strings.Contains(raw, expected) {
			t.Fatalf("expected %q in Jenkins example README", expected)
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
