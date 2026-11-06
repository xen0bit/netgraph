package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/xen0bit/netgraph/internal/agent"
)

func (s *Server) registerAgentRoutes() {
	s.mux.Handle("POST /api/v1/agent/hello", s.requireAgent(s.agentHello))
	s.mux.Handle("POST /api/v1/agent/events", s.requireAgent(s.agentEvents))
	s.mux.Handle("GET /api/v1/agent/policy", s.requireAgent(s.agentPolicy))
	s.mux.Handle("GET /api/v1/agents", s.require(RoleViewer, s.agents))
	s.mux.Handle("GET /api/v1/agents/{name}/processes", s.require(RoleViewer, s.agentProcesses))
	s.mux.Handle("GET /api/v1/agents/{name}/connections", s.require(RoleViewer, s.agentConnections))
}

func (s *Server) agentHello(w http.ResponseWriter, r *http.Request) {
	var h agent.Hello
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&h); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.cfg.Store.RegisterAgent(r.Context(), &h, ""); err != nil {
		s.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) agentEvents(w http.ResponseWriter, r *http.Request) {
	var b agent.Batch
	if err := json.NewDecoder(io.LimitReader(r.Body, 32<<20)).Decode(&b); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	counts, err := s.cfg.Store.IngestAgentBatch(r.Context(), &b)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, map[string]any{"accepted": counts, "seq": b.Seq})
}

func (s *Server) agentPolicy(w http.ResponseWriter, r *http.Request) {
	p, err := s.cfg.Store.AgentPolicy(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, p)
}

func (s *Server) agents(w http.ResponseWriter, r *http.Request) {
	out, err := s.cfg.Store.Agents(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, out)
}

func agentLimit(r *http.Request) int {
	n, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	return n
}

func (s *Server) agentProcesses(w http.ResponseWriter, r *http.Request) {
	out, err := s.cfg.Store.AgentProcesses(r.Context(), r.PathValue("name"), agentLimit(r))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, out)
}

func (s *Server) agentConnections(w http.ResponseWriter, r *http.Request) {
	out, err := s.cfg.Store.AgentConnections(r.Context(), r.PathValue("name"), agentLimit(r))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, out)
}
