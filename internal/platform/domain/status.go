package domain

type HealthStatus struct {
	Service string `json:"service"`
	Status  string `json:"status"`
}

type PingStatus struct {
	Message string `json:"message"`
}

type ReadinessStatus struct {
	Service string          `json:"service"`
	Status  string          `json:"status"`
	Checks  map[string]bool `json:"checks"`
}

func (r ReadinessStatus) Ready() bool {
	for _, passed := range r.Checks {
		if !passed {
			return false
		}
	}

	return true
}
