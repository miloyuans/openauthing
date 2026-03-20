package repo

import "github.com/miloyuans/openauthing/internal/config"

type ReadinessRepository interface {
	Checks() map[string]bool
}

type ConfigReadinessRepository struct {
	cfg config.Config
}

func NewConfigReadinessRepository(cfg config.Config) *ConfigReadinessRepository {
	return &ConfigReadinessRepository{cfg: cfg}
}

func (r *ConfigReadinessRepository) Checks() map[string]bool {
	return map[string]bool{
		"postgres_configured": r.cfg.Postgres.DSN != "",
		"redis_configured":    r.cfg.Redis.Addr != "",
	}
}
