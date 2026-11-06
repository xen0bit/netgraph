package api

import (
	"errors"
	"net/http"
)

var errNoIP = errors.New("ip is required")

func (s *Server) registerGeoRoutes() {
	s.mux.Handle("GET /api/v1/geo", s.require(RoleViewer, s.geoLookup))
	s.mux.Handle("GET /api/v1/geo/status", s.require(RoleViewer, s.geoStatus))
}

func (s *Server) geoLookup(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		httpError(w, http.StatusBadRequest, errNoIP)
		return
	}
	info, ok := s.cfg.Store.GeoLookup(ip)
	writeJSON(w, map[string]any{"ip": ip, "found": ok, "geo": info})
}

func (s *Server) geoStatus(w http.ResponseWriter, r *http.Request) {
	loaded, ranges := s.cfg.Store.GeoStatus()
	writeJSON(w, map[string]any{"loaded": loaded, "ranges": ranges})
}
