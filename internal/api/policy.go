package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/xen0bit/netgraph/internal/policy"
)

var errNoActivePolicy = errors.New("no policy is active")

// registerPolicyRoutes adds the durable policy surface. Version 1 policies
// keep working; version 2 adds precedence, directions, priorities and ask.
func (s *Server) registerPolicyRoutes() {
	s.mux.Handle("GET /api/v1/policies", s.require(RoleViewer, s.policyList))
	s.mux.Handle("POST /api/v1/policies", s.require(RoleOperator, s.policySave))
	s.mux.Handle("GET /api/v1/policies/{id}", s.require(RoleViewer, s.policyGet))
	s.mux.Handle("PUT /api/v1/policies/{id}", s.require(RoleOperator, s.policySave))
	s.mux.Handle("DELETE /api/v1/policies/{id}", s.require(RoleOperator, s.policyDelete))
	s.mux.Handle("POST /api/v1/policies/{id}/activate", s.require(RoleOperator, s.policyActivate))
	s.mux.Handle("GET /api/v1/policies/active", s.require(RoleViewer, s.policyActive))
	s.mux.Handle("POST /api/v1/policy/explain", s.require(RoleViewer, s.policyExplain))
	s.mux.Handle("GET /api/v1/policy/audit", s.require(RoleViewer, s.policyAudit))
}

func (s *Server) policyList(w http.ResponseWriter, r *http.Request) {
	out, err := s.cfg.Store.Policies(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, out)
}

func (s *Server) policyGet(w http.ResponseWriter, r *http.Request) {
	p, err := s.cfg.Store.Policy(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, p)
}

func (s *Server) policyActive(w http.ResponseWriter, r *http.Request) {
	p, err := s.cfg.Store.ActivePolicy(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	if p == nil {
		httpError(w, http.StatusNotFound, errNoActivePolicy)
		return
	}
	writeJSON(w, p)
}

func (s *Server) policySave(w http.ResponseWriter, r *http.Request) {
	p, err := policy.Parse(io.LimitReader(r.Body, 2<<20))
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if id := r.PathValue("id"); id != "" {
		p.ID = id
	}
	saved, err := s.cfg.Store.SavePolicy(r.Context(), p)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, saved)
}

func (s *Server) policyDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.cfg.Store.DeletePolicy(r.Context(), r.PathValue("id")); err != nil {
		s.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) policyActivate(w http.ResponseWriter, r *http.Request) {
	if err := s.cfg.Store.ActivatePolicy(r.Context(), r.PathValue("id")); err != nil {
		s.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type explainRequest struct {
	Policy json.RawMessage `json:"policy"`
	ID     string          `json:"id"`
	Conn   policy.Conn     `json:"conn"`
}

func (s *Server) policyExplain(w http.ResponseWriter, r *http.Request) {
	var in explainRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(&in); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	var p *policy.Policy
	var err error
	switch {
	case len(in.Policy) > 0:
		p, err = policy.Parse(strings.NewReader(string(in.Policy)))
	case in.ID != "":
		p, err = s.cfg.Store.Policy(r.Context(), in.ID)
	default:
		p, err = s.cfg.Store.ActivePolicy(r.Context())
		if p == nil && err == nil {
			err = errNoActivePolicy
		}
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, p.Explain(in.Conn))
}

func (s *Server) policyAudit(w http.ResponseWriter, r *http.Request) {
	var p *policy.Policy
	var err error
	if id := r.URL.Query().Get("id"); id != "" {
		p, err = s.cfg.Store.Policy(r.Context(), id)
	} else {
		p, err = s.cfg.Store.ActivePolicy(r.Context())
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	if p == nil {
		httpError(w, http.StatusNotFound, errNoActivePolicy)
		return
	}
	out, err := s.cfg.Store.AuditPolicy(r.Context(), p)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, out)
}
