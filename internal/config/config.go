package config

import (
	"os"
	"strconv"
	"time"
)

const (
	defaultEnv              = "development"
	defaultHTTPAddr         = ":8080"
	defaultPublicURL        = "http://localhost:8080"
	defaultCookieSecret     = "change-me"
	defaultReadTimeout      = 10 * time.Second
	defaultWriteTimeout     = 15 * time.Second
	defaultIdleTimeout      = 60 * time.Second
	defaultShutdownTimeout  = 10 * time.Second
	defaultPostgresDSN      = "postgres://postgres:postgres@localhost:5432/openauthing?sslmode=disable"
	defaultRedisAddr        = "localhost:6379"
	defaultRedisDB          = 0
)

type Config struct {
	Environment string
	HTTP        HTTPConfig
	Postgres    PostgresConfig
	Redis       RedisConfig
	Security    SecurityConfig
}

type HTTPConfig struct {
	Addr            string
	PublicURL       string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
}

type PostgresConfig struct {
	DSN string
}

type RedisConfig struct {
	Addr     string
	Password string
	DB       int
}

type SecurityConfig struct {
	CookieSecret string
}

func Load() Config {
	return Config{
		Environment: getEnv("OPENAUTHING_ENV", defaultEnv),
		HTTP: HTTPConfig{
			Addr:            getEnv("OPENAUTHING_HTTP_ADDR", defaultHTTPAddr),
			PublicURL:       getEnv("OPENAUTHING_PUBLIC_URL", defaultPublicURL),
			ReadTimeout:     getDuration("OPENAUTHING_HTTP_READ_TIMEOUT", defaultReadTimeout),
			WriteTimeout:    getDuration("OPENAUTHING_HTTP_WRITE_TIMEOUT", defaultWriteTimeout),
			IdleTimeout:     getDuration("OPENAUTHING_HTTP_IDLE_TIMEOUT", defaultIdleTimeout),
			ShutdownTimeout: getDuration("OPENAUTHING_HTTP_SHUTDOWN_TIMEOUT", defaultShutdownTimeout),
		},
		Postgres: PostgresConfig{
			DSN: getEnv("OPENAUTHING_POSTGRES_DSN", defaultPostgresDSN),
		},
		Redis: RedisConfig{
			Addr:     getEnv("OPENAUTHING_REDIS_ADDR", defaultRedisAddr),
			Password: getEnv("OPENAUTHING_REDIS_PASSWORD", ""),
			DB:       getInt("OPENAUTHING_REDIS_DB", defaultRedisDB),
		},
		Security: SecurityConfig{
			CookieSecret: getEnv("OPENAUTHING_COOKIE_SECRET", defaultCookieSecret),
		},
	}
}

func getEnv(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}

	return value
}

func getDuration(key string, fallback time.Duration) time.Duration {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}

	parsed, err := time.ParseDuration(raw)
	if err != nil {
		return fallback
	}

	return parsed
}

func getInt(key string, fallback int) int {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}

	parsed, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}

	return parsed
}
