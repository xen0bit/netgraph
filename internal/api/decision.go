package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/xen0bit/netgraph/internal/store"
)

func (s *Server) registerDecisionRoutes() {
	s.mux.Handle("GET /api/v1/decisions", s.require(RoleViewer, s.decisions))
	s.mux.Handle("GET /api/v1/decisions/{id}", s.require(RoleViewer, s.decisionGet))
	s.mux.Handle("POST /api/v1/decisions/scan", s.require(RoleOperator, s.decisionsScan))
	s.mux.Handle("POST /api/v1/decisions/{id}/allow", s.require(RoleOperator, s.decisionAnswer))
	s.mux.Handle("POST /api/v1/decisions/{id}/deny", s.require(RoleOperator, s.decisionAnswer))
	s.mux.Handle("POST /api/v1/decisions/{id}/rule", s.require(RoleOperator, s.decisionAnswer))
	s.mux.Handle("POST /api/v1/decisions/{id}/reset", s.require(RoleOperator, s.decisionReset))
	s.mux.Handle("POST /api/v1/decisions/expire", s.require(RoleOperator, s.decisionsExpire))
}

func (s *Server) decisions(w http.ResponseWriter, r *http.Request) {
	out, err := s.cfg.Store.Decisions(r.Context(), r.URL.Query().Get("status"), 0)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, out)
}

func (s *Server) decisionGet(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	d, err := s.cfg.Store.Decision(r.Context(), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, map[string]any{"decision": d, "prefilled_rule": store.DecisionRule(*d)})
}

func (s *Server) decisionsScan(w http.ResponseWriter, r *http.Request) {
	var in struct {
		From  string `json:"from"`
		To    string `json:"to"`
		Limit int    `json:"limit"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in)
	f, err := s.policyWindow(in.From, in.To, r.URL.Query())
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	n, err := s.cfg.Store.ScanDecisions(r.Context(), f, in.Limit)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, map[string]any{"created": n})
}

// decisionAnswer records allow or deny once, or (rule) adds a rule for the
// connection to the active policy. Who answered is the caller's identity, not
// something the body can claim.
func (s *Server) decisionAnswer(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	answer := r.URL.Path[strings.LastIndexByte(r.URL.Path, '/')+1:]
	var in struct {
		Action string `json:"action"` // for rule: allow or deny
		Note   string `json:"note"`
	}
	if r.ContentLength != 0 {
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil && err != io.EOF {
			httpError(w, http.StatusBadRequest, err)
			return
		}
	}
	d, err := s.cfg.Store.AnswerDecision(r.Context(), id, answer, in.Action, identityOf(r.Context()).Actor(), in.Note)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, d)
}

func (s *Server) decisionReset(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.cfg.Store.ResetDecision(r.Context(), id); err != nil {
		s.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) decisionsExpire(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Before int64 `json:"before"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in)
	n, err := s.cfg.Store.ExpireDecisions(r.Context(), in.Before)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, map[string]any{"expired": n})
}
