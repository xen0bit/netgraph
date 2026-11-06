package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xen0bit/netgraph/internal/policy"
)

func TestClientProtocol(t *testing.T) {
	var gotHello Hello
	var gotBatch Batch
	var gotPolicy bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "token", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/v1/agent/hello":
			_ = json.NewDecoder(r.Body).Decode(&gotHello)
			w.WriteHeader(http.StatusNoContent)
		case "/api/v1/agent/events":
			_ = json.NewDecoder(r.Body).Decode(&gotBatch)
			_, _ = w.Write([]byte(`{"accepted":{},"seq":1}`))
		case "/api/v1/agent/policy":
			gotPolicy = true
			_ = json.NewEncoder(w).Encode(PolicyResponse{
				Policy:  &policy.Policy{Version: 2, Defaults: policy.Defaults{Egress: "deny", Ingress: "deny", IntraZone: "allow", DNS: "allow"}},
				Profile: "home", Mode: "alert", Hash: "abc",
			})
		}
	}))
	defer srv.Close()
	c := &Client{Base: srv.URL, Token: "tok", Agent: "laptop", Boot: "boot1"}
	if err := c.Hello(context.Background(), &Hello{Name: "laptop", OS: "linux"}); err != nil {
		t.Fatal(err)
	}
	if gotHello.Name != "laptop" {
		t.Fatalf("hello = %+v", gotHello)
	}
	if err := c.Send(context.Background(), &Batch{Connections: []Connection{{Key: "k"}}}); err != nil {
		t.Fatal(err)
	}
	if gotBatch.Seq != 1 || gotBatch.Agent != "laptop" || gotBatch.Version != Version {
		t.Fatalf("batch = %+v", gotBatch)
	}
	p, err := c.Policy(context.Background())
	if err != nil || !gotPolicy || p.Profile != "home" || p.Hash != "abc" {
		t.Fatalf("policy = %+v, %v", p, err)
	}
}

type fakeScanner struct{}

func (fakeScanner) Scan(context.Context) ([]Process, []Connection, error) {
	return []Process{{PID: 1, Path: "/bin/sh"}}, []Connection{{Key: "k", RemoteIP: "203.0.113.9", RemotePort: 443, Proto: "tcp", Direction: "out", App: "curl"}}, nil
}

type fakeEnforcer struct{}

func (fakeEnforcer) Apply(context.Context, []Connection) ([]Actual, error) {
	return []Actual{{Key: "k", Action: "deny"}}, nil
}
func (fakeEnforcer) Close() error { return nil }

func TestRunnerOnce(t *testing.T) {
	var got Batch
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agent/hello":
			w.WriteHeader(http.StatusNoContent)
		case "/api/v1/agent/policy":
			_ = json.NewEncoder(w).Encode(PolicyResponse{Policy: &policy.Policy{Version: 2, Defaults: policy.Defaults{Egress: "deny", Ingress: "deny", IntraZone: "allow", DNS: "allow"}}})
		case "/api/v1/agent/events":
			_ = json.NewDecoder(r.Body).Decode(&got)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()
	r := &Runner{Client: &Client{Base: srv.URL, Agent: "laptop", Boot: "b"}, Scanner: fakeScanner{}, Enforcer: fakeEnforcer{}}
	if err := r.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(got.Connections) != 1 || got.Connections[0].Predicted != "deny" || got.Connections[0].Actual != "deny" || got.Actuals == nil {
		t.Fatalf("batch = %+v", got)
	}
}

func TestPredictScope(t *testing.T) {
	p := &policy.Policy{Version: 2, Defaults: policy.Defaults{Egress: "deny", Ingress: "deny", IntraZone: "allow", DNS: "allow"},
		RulesV2: []policy.RuleV2{
			{ID: "r1", Name: "no tracker", Action: policy.ActionDeny, Remote: policy.Selector{Type: "ip", Values: []string{"203.0.113.9"}}},
			{ID: "r2", Name: "no curl", Action: policy.ActionDeny, Local: policy.Selector{Type: "app", Values: []string{"curl"}}, Remote: policy.Selector{Type: "ip", Values: []string{"203.0.113.10"}}},
			{ID: "r3", Name: "https", Action: policy.ActionAllow, Ports: []string{"443/tcp"}},
		}}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	pr := &PolicyResponse{Policy: p}
	for _, tc := range []struct {
		c             Connection
		action, scope string
	}{
		{Connection{Direction: "out", RemoteIP: "203.0.113.9", RemotePort: 80, Proto: "tcp"}, "deny", ScopeHost},
		{Connection{Direction: "out", RemoteIP: "203.0.113.10", RemotePort: 80, Proto: "tcp", App: "curl"}, "deny", ScopeProcess},
		{Connection{Direction: "out", RemoteIP: "198.51.100.1", RemotePort: 22, Proto: "tcp"}, "deny", ScopeDefault},
		{Connection{Direction: "out", RemoteIP: "198.51.100.1", RemotePort: 443, Proto: "tcp6"}, "allow", ScopeHost},
	} {
		action, scope, _, _ := predict(pr, tc.c)
		if action != tc.action || scope != tc.scope {
			t.Errorf("%+v: %s %s, want %s %s", tc.c, action, scope, tc.action, tc.scope)
		}
	}
}
