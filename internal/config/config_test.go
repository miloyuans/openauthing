package config

import (
	"os"
	"path/filepath"
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
		"session": {"secret":"file-secret"}
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
		"session": {"secret":"file-secret"}
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
}
