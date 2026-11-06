package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/policy/blocklist"
)

func (s *Server) registerBlocklistRoutes() {
	s.mux.Handle("GET /api/v1/blocklists", s.require(RoleViewer, s.blocklists))
	s.mux.Handle("POST /api/v1/blocklists", s.require(RoleOperator, s.saveBlocklist))
	s.mux.Handle("GET /api/v1/blocklists/{id}", s.require(RoleViewer, s.blocklistGet))
	s.mux.Handle("PUT /api/v1/blocklists/{id}", s.require(RoleOperator, s.saveBlocklist))
	s.mux.Handle("DELETE /api/v1/blocklists/{id}", s.require(RoleOperator, s.blocklistDelete))
	s.mux.Handle("GET /api/v1/blocklists/{id}/entries", s.require(RoleViewer, s.blocklistEntries))
	s.mux.Handle("PATCH /api/v1/blocklists/{id}/entries/{entry}", s.require(RoleOperator, s.blocklistEntrySet))
	s.mux.Handle("POST /api/v1/blocklists/{id}/import", s.require(RoleOperator, s.blocklistImport))
	s.mux.Handle("POST /api/v1/blocklists/{id}/update", s.require(RoleOperator, s.blocklistUpdate))
	s.mux.Handle("GET /api/v1/rule-groups", s.require(RoleViewer, s.ruleGroups))
	s.mux.Handle("POST /api/v1/rule-groups", s.require(RoleOperator, s.saveRuleGroup))
}

func (s *Server) blocklists(w http.ResponseWriter, r *http.Request) {
	out, err := s.cfg.Store.Blocklists(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, out)
}

func blocklistID(r *http.Request) (int64, error) {
	return strconv.ParseInt(r.PathValue("id"), 10, 64)
}

func (s *Server) blocklistGet(w http.ResponseWriter, r *http.Request) {
	id, err := blocklistID(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	b, err := s.cfg.Store.Blocklist(r.Context(), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, b)
}

func (s *Server) saveBlocklist(w http.ResponseWriter, r *http.Request) {
	var b model.Blocklist
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&b); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if id := r.PathValue("id"); id != "" {
		n, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			httpError(w, http.StatusBadRequest, err)
			return
		}
		b.ID = n
	}
	saved, err := s.cfg.Store.SaveBlocklist(r.Context(), &b)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, saved)
}

func (s *Server) blocklistDelete(w http.ResponseWriter, r *http.Request) {
	id, err := blocklistID(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.cfg.Store.DeleteBlocklist(r.Context(), id); err != nil {
		s.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) blocklistEntries(w http.ResponseWriter, r *http.Request) {
	id, err := blocklistID(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	out, err := s.cfg.Store.BlocklistEntries(r.Context(), id, r.URL.Query().Get("enabled") == "1", limit, offset)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, out)
}

func (s *Server) blocklistEntrySet(w http.ResponseWriter, r *http.Request) {
	id, err := blocklistID(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	entry, err := strconv.ParseInt(r.PathValue("entry"), 10, 64)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	var in struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.cfg.Store.SetBlocklistEntry(r.Context(), id, entry, in.Enabled); err != nil {
		s.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) blocklistImport(w http.ResponseWriter, r *http.Request) {
	id, err := blocklistID(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	var in struct {
		Text   string `json:"text"`
		Format string `json:"format"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<20)).Decode(&in); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	parsed, err := blocklist.Parse(strings.NewReader(in.Text), in.Format)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.cfg.Store.ReplaceBlocklistEntries(r.Context(), id, parsed); err != nil {
		s.fail(w, err)
		return
	}
	b, err := s.cfg.Store.Blocklist(r.Context(), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, b)
}

// blocklistUpdate fetches a blocklist's URL now, over HTTPS to a public address.
func (s *Server) blocklistUpdate(w http.ResponseWriter, r *http.Request) {
	id, err := blocklistID(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	// Always the default fetcher: an HTTP client may not turn off the check
	// that keeps the server from fetching addresses on its own network.
	f := &blocklist.Fetcher{}
	b, err := s.cfg.Store.UpdateBlocklist(r.Context(), id, f)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, b)
}

func (s *Server) ruleGroups(w http.ResponseWriter, r *http.Request) {
	out, err := s.cfg.Store.RuleGroups(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, out)
}

func (s *Server) saveRuleGroup(w http.ResponseWriter, r *http.Request) {
	var g model.RuleGroup
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&g); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	saved, err := s.cfg.Store.SaveRuleGroup(r.Context(), &g)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, saved)
}
