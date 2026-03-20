package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
)

const (
	defaultAppName        = "openauthing"
	defaultAppEnv         = "development"
	defaultHTTPAddr       = ":8080"
	defaultPostgresDSN    = "postgres://openauthing@localhost:5432/openauthing?sslmode=disable"
	defaultRedisAddr      = "localhost:6379"
	defaultAllowedOrigins = "http://localhost:5173"
	defaultLogLevel       = "info"
	defaultSessionSecret  = "change-me-in-local-dev-only"
	defaultOIDCIssuer     = "http://localhost:8080"
	defaultOIDCCodeTTL    = 300
)

type Config struct {
	App      AppConfig      `json:"app"`
	HTTP     HTTPConfig     `json:"http"`
	Postgres PostgresConfig `json:"postgres"`
	Redis    RedisConfig    `json:"redis"`
	Log      LogConfig      `json:"log"`
	Session  SessionConfig  `json:"session"`
	OIDC     OIDCConfig     `json:"oidc"`
}

type AppConfig struct {
	Name string `json:"name"`
	Env  string `json:"env"`
}

type HTTPConfig struct {
	Addr           string   `json:"addr"`
	AllowedOrigins []string `json:"allowed_origins"`
}

type PostgresConfig struct {
	DSN string `json:"dsn"`
}

type RedisConfig struct {
	Addr string `json:"addr"`
}

type LogConfig struct {
	Level string `json:"level"`
}

type SessionConfig struct {
	Secret string `json:"secret"`
}

type OIDCConfig struct {
	Issuer                      string `json:"issuer"`
	SigningKeyFile              string `json:"signing_key_file"`
	AuthorizationCodeTTLSeconds int    `json:"authorization_code_ttl_seconds"`
}

func Load() (Config, error) {
	cfg := Config{
		App: AppConfig{
			Name: defaultAppName,
			Env:  defaultAppEnv,
		},
		HTTP: HTTPConfig{
			Addr:           defaultHTTPAddr,
			AllowedOrigins: []string{"http://localhost:5173"},
		},
		Postgres: PostgresConfig{
			DSN: defaultPostgresDSN,
		},
		Redis: RedisConfig{
			Addr: defaultRedisAddr,
		},
		Log: LogConfig{
			Level: defaultLogLevel,
		},
		Session: SessionConfig{
			Secret: defaultSessionSecret,
		},
		OIDC: OIDCConfig{
			Issuer:                      defaultOIDCIssuer,
			AuthorizationCodeTTLSeconds: defaultOIDCCodeTTL,
		},
	}

	if path := strings.TrimSpace(os.Getenv("OPENAUTHING_CONFIG_FILE")); path != "" {
		if err := loadFile(path, &cfg); err != nil {
			return Config{}, err
		}
	}

	cfg.App.Name = getEnv("OPENAUTHING_APP_NAME", cfg.App.Name)
	cfg.App.Env = getEnv("OPENAUTHING_ENV", cfg.App.Env)
	cfg.HTTP.Addr = getEnv("OPENAUTHING_HTTP_ADDR", cfg.HTTP.Addr)
	cfg.Postgres.DSN = getEnv("OPENAUTHING_POSTGRES_DSN", cfg.Postgres.DSN)
	cfg.Redis.Addr = getEnv("OPENAUTHING_REDIS_ADDR", cfg.Redis.Addr)
	cfg.Log.Level = getEnv("OPENAUTHING_LOG_LEVEL", cfg.Log.Level)
	cfg.Session.Secret = getEnv("OPENAUTHING_SESSION_SECRET", cfg.Session.Secret)
	cfg.OIDC.Issuer = getEnv("OPENAUTHING_OIDC_ISSUER", cfg.OIDC.Issuer)
	cfg.OIDC.SigningKeyFile = getEnv("OPENAUTHING_OIDC_SIGNING_KEY_FILE", cfg.OIDC.SigningKeyFile)
	cfg.OIDC.AuthorizationCodeTTLSeconds = getEnvInt(
		"OPENAUTHING_OIDC_AUTHORIZATION_CODE_TTL_SECONDS",
		cfg.OIDC.AuthorizationCodeTTLSeconds,
	)

	if origins, ok := lookupEnv("OPENAUTHING_HTTP_ALLOWED_ORIGINS"); ok {
		cfg.HTTP.AllowedOrigins = splitCSV(origins)
	} else if len(cfg.HTTP.AllowedOrigins) == 0 {
		cfg.HTTP.AllowedOrigins = splitCSV(defaultAllowedOrigins)
	}

	if err := cfg.validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func loadFile(path string, cfg *Config) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config file %q: %w", path, err)
	}

	if err := json.Unmarshal(raw, cfg); err != nil {
		return fmt.Errorf("decode config file %q: %w", path, err)
	}

	return nil
}

func (c Config) validate() error {
	if strings.TrimSpace(c.App.Name) == "" {
		return fmt.Errorf("app.name must not be empty")
	}

	if strings.TrimSpace(c.HTTP.Addr) == "" {
		return fmt.Errorf("http.addr must not be empty")
	}

	if strings.TrimSpace(c.Postgres.DSN) == "" {
		return fmt.Errorf("postgres.dsn must not be empty")
	}

	if strings.TrimSpace(c.Redis.Addr) == "" {
		return fmt.Errorf("redis.addr must not be empty")
	}

	if strings.TrimSpace(c.Log.Level) == "" {
		return fmt.Errorf("log.level must not be empty")
	}

	if strings.TrimSpace(c.Session.Secret) == "" {
		return fmt.Errorf("session.secret must not be empty")
	}

	if err := validateOIDCIssuer(c.OIDC.Issuer); err != nil {
		return err
	}

	if c.OIDC.AuthorizationCodeTTLSeconds <= 0 {
		return fmt.Errorf("oidc.authorization_code_ttl_seconds must be greater than 0")
	}

	return nil
}

func validateOIDCIssuer(raw string) error {
	issuer := strings.TrimSpace(raw)
	if issuer == "" {
		return fmt.Errorf("oidc.issuer must not be empty")
	}

	parsed, err := url.Parse(issuer)
	if err != nil {
		return fmt.Errorf("oidc.issuer must be a valid URL: %w", err)
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("oidc.issuer must use http or https")
	}

	if strings.TrimSpace(parsed.Host) == "" {
		return fmt.Errorf("oidc.issuer host must not be empty")
	}

	return nil
}

func getEnv(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}

	return value
}

func lookupEnv(key string) (string, bool) {
	value, ok := os.LookupEnv(key)
	if !ok || value == "" {
		return "", false
	}

	return value, true
}

func getEnvInt(key string, fallback int) int {
	raw, ok := lookupEnv(key)
	if !ok {
		return fallback
	}

	var value int
	if _, err := fmt.Sscanf(raw, "%d", &value); err != nil {
		return fallback
	}

	return value
}

func splitCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			values = append(values, trimmed)
		}
	}

	return values
}
