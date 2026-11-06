package api

import "net/http"

func (s *Server) connections(w http.ResponseWriter, r *http.Request) {
	f, ok := s.filter(w, r)
	if !ok {
		return
	}
	out, err := s.cfg.Store.ConnectionGroups(r.Context(), f, r.URL.Query().Get("group"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, out)
}
