package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadFromConfigFile(t *testing.T) {
	for _, key := range []string{
		"OPENAUTHING_APP_NAME",
		"OPENAUTHING_ENV",
		"OPENAUTHING_HTTP_ADDR",
		"OPENAUTHING_HTTP_ALLOWED_ORIGINS",
		"OPENAUTHING_POSTGRES_DSN",
		"OPENAUTHING_REDIS_ADDR",
		"OPENAUTHING_LOG_LEVEL",
		"OPENAUTHING_SESSION_SECRET",
		"OPENAUTHING_OIDC_ISSUER",
		"OPENAUTHING_OIDC_SIGNING_KEY_FILE",
		"OPENAUTHING_OIDC_AUTHORIZATION_CODE_TTL_SECONDS",
	} {
		t.Setenv(key, "")
	}

	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")

	content := `{
		"app": {"name":"file-app","env":"test"},
		"http": {"addr":":9090","allowed_origins":["http://localhost:3000"]},
		"postgres": {"dsn":"postgres://from-file"},
		"redis": {"addr":"redis-from-file:6379"},
		"log": {"level":"debug"},
		"session": {"secret":"file-secret"},
		"oidc": {"issuer":"https://iam.example.test","signing_key_file":"./keys/oidc.pem","authorization_code_ttl_seconds":180}
	}`

	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	t.Setenv("OPENAUTHING_CONFIG_FILE", configPath)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if cfg.App.Name != "file-app" || cfg.Log.Level != "debug" || cfg.Session.Secret != "file-secret" {
		t.Fatalf("unexpected config values: %#v", cfg)
	}

	if cfg.OIDC.Issuer != "https://iam.example.test" || cfg.OIDC.SigningKeyFile != "./keys/oidc.pem" {
		t.Fatalf("unexpected config values: %#v", cfg)
	}

	if cfg.OIDC.AuthorizationCodeTTLSeconds != 180 {
		t.Fatalf("unexpected config values: %#v", cfg)
	}
}

func TestLoadEnvironmentOverridesConfigFile(t *testing.T) {
	for _, key := range []string{
		"OPENAUTHING_APP_NAME",
		"OPENAUTHING_ENV",
		"OPENAUTHING_HTTP_ADDR",
		"OPENAUTHING_HTTP_ALLOWED_ORIGINS",
		"OPENAUTHING_POSTGRES_DSN",
		"OPENAUTHING_REDIS_ADDR",
		"OPENAUTHING_LOG_LEVEL",
		"OPENAUTHING_SESSION_SECRET",
		"OPENAUTHING_OIDC_ISSUER",
		"OPENAUTHING_OIDC_SIGNING_KEY_FILE",
		"OPENAUTHING_OIDC_AUTHORIZATION_CODE_TTL_SECONDS",
	} {
		t.Setenv(key, "")
	}

	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")

	content := `{
		"app": {"name":"file-app","env":"test"},
		"http": {"addr":":9090","allowed_origins":["http://localhost:3000"]},
		"postgres": {"dsn":"postgres://from-file"},
		"redis": {"addr":"redis-from-file:6379"},
		"log": {"level":"debug"},
		"session": {"secret":"file-secret"},
		"oidc": {"issuer":"https://iam.example.test","signing_key_file":"./keys/oidc.pem","authorization_code_ttl_seconds":180}
	}`

	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	t.Setenv("OPENAUTHING_CONFIG_FILE", configPath)
	t.Setenv("OPENAUTHING_APP_NAME", "env-app")
	t.Setenv("OPENAUTHING_HTTP_ADDR", ":8088")
	t.Setenv("OPENAUTHING_POSTGRES_DSN", "postgres://from-env")
	t.Setenv("OPENAUTHING_REDIS_ADDR", "redis-env:6379")
	t.Setenv("OPENAUTHING_LOG_LEVEL", "warn")
	t.Setenv("OPENAUTHING_SESSION_SECRET", "env-secret")
	t.Setenv("OPENAUTHING_HTTP_ALLOWED_ORIGINS", "http://localhost:5173,http://localhost:4173")
	t.Setenv("OPENAUTHING_OIDC_ISSUER", "https://env.example.test")
	t.Setenv("OPENAUTHING_OIDC_SIGNING_KEY_FILE", "./keys/env-oidc.pem")
	t.Setenv("OPENAUTHING_OIDC_AUTHORIZATION_CODE_TTL_SECONDS", "240")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if cfg.App.Name != "env-app" {
		t.Fatalf("expected env app name, got %q", cfg.App.Name)
	}

	if cfg.Log.Level != "warn" || cfg.Session.Secret != "env-secret" {
		t.Fatalf("expected env overrides for log/session, got %#v", cfg)
	}

	if len(cfg.HTTP.AllowedOrigins) != 2 {
		t.Fatalf("expected 2 allowed origins, got %#v", cfg.HTTP.AllowedOrigins)
	}

	if cfg.OIDC.Issuer != "https://env.example.test" || cfg.OIDC.SigningKeyFile != "./keys/env-oidc.pem" {
		t.Fatalf("expected env overrides for oidc, got %#v", cfg.OIDC)
	}

	if cfg.OIDC.AuthorizationCodeTTLSeconds != 240 {
		t.Fatalf("expected env overrides for oidc, got %#v", cfg.OIDC)
	}
}

func TestLoadRejectsInvalidOIDCIssuer(t *testing.T) {
	for _, key := range []string{
		"OPENAUTHING_APP_NAME",
		"OPENAUTHING_ENV",
		"OPENAUTHING_HTTP_ADDR",
		"OPENAUTHING_HTTP_ALLOWED_ORIGINS",
		"OPENAUTHING_POSTGRES_DSN",
		"OPENAUTHING_REDIS_ADDR",
		"OPENAUTHING_LOG_LEVEL",
		"OPENAUTHING_SESSION_SECRET",
		"OPENAUTHING_OIDC_ISSUER",
		"OPENAUTHING_OIDC_SIGNING_KEY_FILE",
		"OPENAUTHING_OIDC_AUTHORIZATION_CODE_TTL_SECONDS",
	} {
		t.Setenv(key, "")
	}

	t.Setenv("OPENAUTHING_OIDC_ISSUER", "not-a-url")

	_, err := Load()
	if err == nil {
		t.Fatal("expected invalid oidc issuer error")
	}

	if !strings.Contains(err.Error(), "oidc.issuer") {
		t.Fatalf("expected oidc issuer validation error, got %v", err)
	}
}
