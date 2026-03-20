package service

import (
	"github.com/miloyuans/openauthing/internal/platform/domain"
	"github.com/miloyuans/openauthing/internal/platform/repo"
)

type StatusService struct {
	serviceName string
	readiness   repo.ReadinessRepository
}

func NewStatusService(serviceName string, readiness repo.ReadinessRepository) *StatusService {
	return &StatusService{
		serviceName: serviceName,
		readiness:   readiness,
	}
}

func (s *StatusService) Health() domain.HealthStatus {
	return domain.HealthStatus{
		Service: s.serviceName,
		Status:  "ok",
	}
}

func (s *StatusService) Ping() domain.PingStatus {
	return domain.PingStatus{
		Message: "pong",
	}
}

func (s *StatusService) Readiness() domain.ReadinessStatus {
	status := domain.ReadinessStatus{
		Service: s.serviceName,
		Status:  "ready",
		Checks:  s.readiness.Checks(),
	}

	if !status.Ready() {
		status.Status = "not_ready"
	}

	return status
}
