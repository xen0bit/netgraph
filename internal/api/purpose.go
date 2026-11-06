package api

import (
	"io"
	"net/http"
	"strconv"

	"github.com/xen0bit/netgraph/internal/purpose"
)

func (s *Server) registerPurposeRoutes() {
	s.mux.Handle("GET /api/v1/purposes", s.require(RoleViewer, s.purposes))
	s.mux.Handle("POST /api/v1/purposes", s.require(RoleOperator, s.importPurpose))
	s.mux.Handle("DELETE /api/v1/purposes/{id}", s.require(RoleOperator, s.deletePurpose))
}

func (s *Server) purposes(w http.ResponseWriter, r *http.Request) {
	if host := r.URL.Query().Get("host"); host != "" {
		out, err := s.cfg.Store.PurposeFor(r.Context(), host)
		if err != nil {
			s.fail(w, err)
			return
		}
		writeJSON(w, out)
		return
	}
	out, err := s.cfg.Store.Purposes(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, out)
}

func (s *Server) importPurpose(w http.ResponseWriter, r *http.Request) {
	m, err := purpose.Parse(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	n, err := s.cfg.Store.ImportPurpose(r.Context(), m)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, map[string]any{"application": m.Application, "imported": n})
}

func (s *Server) deletePurpose(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.cfg.Store.DeletePurpose(r.Context(), id); err != nil {
		s.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
