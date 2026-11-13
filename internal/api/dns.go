package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/xen0bit/netgraph/internal/model"
)

// DNSServer is netgraph's own DNS server, when it runs.
type DNSServer interface {
	Status() *model.DNSServerStatus
	// Reload rereads the rules soon: a person just changed them.
	Reload()
}

func (s *Server) registerDNSRoutes() {
	s.mux.Handle("GET /api/v1/dns/server", s.require(RoleViewer, s.dnsServer))
	s.mux.Handle("GET /api/v1/dns/stats", s.require(RoleViewer, s.memoized(false, func(w http.ResponseWriter, r *http.Request) {
		answer(s, w, r, s.cfg.Store.DNSStats)
	})))
	s.mux.Handle("GET /api/v1/dns/rules", s.require(RoleViewer, s.dnsRules))
	s.mux.Handle("POST /api/v1/dns/rules", s.require(RoleOperator, s.saveDNSRule))
	s.mux.Handle("PUT /api/v1/dns/rules/{id}", s.require(RoleOperator, s.saveDNSRule))
	s.mux.Handle("DELETE /api/v1/dns/rules/{id}", s.require(RoleOperator, s.deleteDNSRule))
	s.mux.Handle("POST /api/v1/dns/block", s.require(RoleOperator, s.dnsBlock))
}

func (s *Server) dnsServer(w http.ResponseWriter, r *http.Request) {
	if s.cfg.DNS == nil {
		writeJSON(w, &model.DNSServerStatus{})
		return
	}
	writeJSON(w, s.cfg.DNS.Status())
}

func (s *Server) dnsRules(w http.ResponseWriter, r *http.Request) {
	out, err := s.cfg.Store.DNSRules(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, out)
}

func (s *Server) dnsChanged() {
	if s.cfg.DNS != nil {
		s.cfg.DNS.Reload()
	}
}

func (s *Server) saveDNSRule(w http.ResponseWriter, r *http.Request) {
	var rule model.DNSRule
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&rule); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	rule.ID = 0
	if r.PathValue("id") != "" {
		id, err := idParam(r)
		if err != nil {
			httpError(w, http.StatusBadRequest, err)
			return
		}
		rule.ID = id
	}
	saved, err := s.cfg.Store.SaveDNSRule(r.Context(), &rule)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.dnsChanged()
	writeJSON(w, saved)
}

func (s *Server) deleteDNSRule(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.cfg.Store.DeleteDNSRule(r.Context(), id); err != nil {
		s.fail(w, err)
		return
	}
	s.dnsChanged()
	w.WriteHeader(http.StatusNoContent)
}

// dnsBlock is the one-click form: block (or allow) a name for everyone, or
// for one device ("device:<mac>" or a MAC).
func (s *Server) dnsBlock(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name   string `json:"name"`
		Action string `json:"action"`
		Device string `json:"device"`
		Note   string `json:"note"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if req.Action == "" {
		req.Action = model.DNSBlock
	}
	if req.Name == "" {
		httpError(w, http.StatusBadRequest, errors.New("name is required"))
		return
	}
	rule := model.DNSRule{Scope: model.DNSScopeAll, Action: req.Action, Pattern: req.Name, Note: req.Note}
	if req.Device != "" {
		rule.Scope, rule.ScopeValue = model.DNSScopeDevice, strings.TrimPrefix(req.Device, "device:")
	}
	saved, err := s.cfg.Store.SaveDNSRule(r.Context(), &rule)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.dnsChanged()
	writeJSON(w, saved)
}
