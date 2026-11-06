package api

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/xen0bit/netgraph/internal/agent"
	"github.com/xen0bit/netgraph/internal/apiclient"
	"github.com/xen0bit/netgraph/internal/policy"
	"github.com/xen0bit/netgraph/internal/store"
)

func TestAgentAPI(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "ng.db"), store.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	srv := httptest.NewServer(New(Config{Store: st, ReadToken: "rd", AgentToken: "agent"}))
	defer srv.Close()
	ctx := context.Background()
	ac := &agent.Client{Base: srv.URL, Token: "agent", Agent: "laptop", Boot: "boot1"}
	if err := ac.Hello(ctx, &agent.Hello{Name: "laptop", Host: "laptop", OS: "linux"}); err != nil {
		t.Fatal(err)
	}
	if err := ac.Send(ctx, &agent.Batch{Connections: []agent.Connection{{
		Key: "k", Proto: "tcp", RemoteIP: "203.0.113.9", RemotePort: 443, Direction: "out", PID: 7, App: "curl", Predicted: "allow",
	}}}); err != nil {
		t.Fatal(err)
	}
	// The agent token reaches the agent API, not the read API.
	if _, err := (&agent.Client{Base: srv.URL, Token: "rd"}).Policy(ctx); err == nil {
		t.Fatal("read token reached agent policy")
	}
	pol, err := st.SavePolicy(ctx, &policy.Policy{Version: 2, Name: "agent", Defaults: policy.Defaults{Egress: "deny", Ingress: "deny", IntraZone: "allow", DNS: "allow"}, RulesV2: []policy.RuleV2{{Name: "x", Action: policy.ActionAllow, Local: policy.Selector{Type: "any"}, Remote: policy.Selector{Type: "any"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.ActivatePolicy(ctx, pol.ID); err != nil {
		t.Fatal(err)
	}
	got, err := ac.Policy(ctx)
	if err != nil || got.Policy == nil || got.Hash == "" {
		t.Fatalf("policy = %+v, %v", got, err)
	}
	rc := apiclient.NewClient(srv.URL, "rd")
	agents, err := rc.Agents(ctx)
	if err != nil || len(agents) != 1 || agents[0].Name != "laptop" || agents[0].Connections != 1 {
		t.Fatalf("agents = %+v, %v", agents, err)
	}
	conns, err := rc.AgentConnections(ctx, "laptop", 10)
	if err != nil || len(conns) != 1 || conns[0].App != "curl" {
		t.Fatalf("connections = %+v, %v", conns, err)
	}
}
