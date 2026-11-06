package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/xen0bit/netgraph/internal/model"
)

func (s *Server) registerProfileRoutes() {
	s.mux.Handle("GET /api/v1/profiles", s.require(RoleViewer, s.profiles))
	s.mux.Handle("POST /api/v1/profiles", s.require(RoleOperator, s.saveProfile))
	s.mux.Handle("GET /api/v1/profiles/{id}", s.require(RoleViewer, s.profileGet))
	s.mux.Handle("PUT /api/v1/profiles/{id}", s.require(RoleOperator, s.saveProfile))
	s.mux.Handle("DELETE /api/v1/profiles/{id}", s.require(RoleOperator, s.profileDelete))
	s.mux.Handle("POST /api/v1/profiles/{id}/activate", s.require(RoleOperator, s.profileActivate))
	s.mux.Handle("POST /api/v1/profiles/evaluate", s.require(RoleOperator, s.profileEvaluate))
	s.mux.Handle("GET /api/v1/network", s.require(RoleViewer, s.networkContext))
	s.mux.Handle("GET /api/v1/network-triggers", s.require(RoleViewer, s.networkTriggers))
	s.mux.Handle("POST /api/v1/network-triggers", s.require(RoleOperator, s.saveNetworkTrigger))
	s.mux.Handle("DELETE /api/v1/network-triggers/{id}", s.require(RoleOperator, s.deleteNetworkTrigger))
}

func (s *Server) profiles(w http.ResponseWriter, r *http.Request) {
	out, err := s.cfg.Store.Profiles(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, out)
}

func idParam(r *http.Request) (int64, error) {
	return strconv.ParseInt(r.PathValue("id"), 10, 64)
}

func (s *Server) profileGet(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	p, err := s.cfg.Store.Profile(r.Context(), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, p)
}

func (s *Server) saveProfile(w http.ResponseWriter, r *http.Request) {
	var p model.Profile
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&p); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if id := r.PathValue("id"); id != "" {
		n, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			httpError(w, http.StatusBadRequest, err)
			return
		}
		p.ID = n
	}
	saved, err := s.cfg.Store.SaveProfile(r.Context(), &p)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, saved)
}

func (s *Server) profileDelete(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.cfg.Store.DeleteProfile(r.Context(), id); err != nil {
		s.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) profileActivate(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.cfg.Store.ActivateProfile(r.Context(), id); err != nil {
		s.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) profileEvaluate(w http.ResponseWriter, r *http.Request) {
	p, err := s.cfg.Store.EvaluateProfile(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	if p == nil {
		writeJSON(w, map[string]any{"profile": nil})
		return
	}
	writeJSON(w, p)
}

func (s *Server) networkContext(w http.ResponseWriter, r *http.Request) {
	out, err := s.cfg.Store.NetworkContext(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, out)
}

func (s *Server) networkTriggers(w http.ResponseWriter, r *http.Request) {
	out, err := s.cfg.Store.NetworkTriggers(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, out)
}

func (s *Server) saveNetworkTrigger(w http.ResponseWriter, r *http.Request) {
	var t model.NetworkTrigger
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&t); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	saved, err := s.cfg.Store.SaveNetworkTrigger(r.Context(), &t)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, saved)
}

func (s *Server) deleteNetworkTrigger(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.cfg.Store.DeleteNetworkTrigger(r.Context(), id); err != nil {
		s.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
