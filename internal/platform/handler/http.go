package handler

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/miloyuans/openauthing/internal/platform/service"
	"github.com/miloyuans/openauthing/internal/shared/apierror"
	"github.com/miloyuans/openauthing/internal/shared/httpjson"
)

type StatusHandler struct {
	service *service.StatusService
}

func NewStatusHandler(service *service.StatusService) *StatusHandler {
	return &StatusHandler{service: service}
}

func (h *StatusHandler) Register(r chi.Router) {
	r.Get("/healthz", h.handleHealthz)
	r.Get("/readyz", h.handleReadyz)
}

func (h *StatusHandler) RegisterAPI(r chi.Router) {
	r.Get("/ping", h.handlePing)
}

func (h *StatusHandler) handleHealthz(w http.ResponseWriter, r *http.Request) {
	_ = httpjson.Write(w, r, http.StatusOK, h.service.Health())
}

func (h *StatusHandler) handleReadyz(w http.ResponseWriter, r *http.Request) {
	status := h.service.Readiness()
	if !status.Ready() {
		_ = httpjson.WriteAPIError(w, r, apierror.ServiceNotReady())
		return
	}

	_ = httpjson.Write(w, r, http.StatusOK, status)
}

func (h *StatusHandler) handlePing(w http.ResponseWriter, r *http.Request) {
	_ = httpjson.Write(w, r, http.StatusOK, h.service.Ping())
}
