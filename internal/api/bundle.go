package api

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/xen0bit/netgraph/internal/backup"
)

func (s *Server) registerBundleRoutes() {
	s.mux.Handle("GET /api/v1/policy/bundle", s.require(RoleViewer, s.exportBundle))
	s.mux.Handle("POST /api/v1/policy/bundle", s.require(RoleOperator, s.importBundle))
}

func (s *Server) exportBundle(w http.ResponseWriter, r *http.Request) {
	b, err := s.cfg.Store.ExportBundle(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, b)
}

func (s *Server) importBundle(w http.ResponseWriter, r *http.Request) {
	b, err := backup.Parse(io.LimitReader(r.Body, 64<<20))
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	counts, err := s.cfg.Store.ImportBundle(r.Context(), b)
	if err != nil {
		s.fail(w, err)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"imported": counts})
}
