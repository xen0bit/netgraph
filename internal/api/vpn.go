package api

import (
	"net/http"
	"strconv"
)

func (s *Server) registerVPNRoutes() {
	s.mux.Handle("GET /api/v1/vpn/sessions", s.require(RoleViewer, s.vpnSessions))
}

// vpnSessions lists the VPN sessions edges reported in the window, with the
// traffic attributed to each.
func (s *Server) vpnSessions(w http.ResponseWriter, r *http.Request) {
	f, ok := s.filter(w, r)
	if !ok {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	out, err := s.cfg.Store.VPNSessions(r.Context(), f.From, f.To, limit)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, out)
}
