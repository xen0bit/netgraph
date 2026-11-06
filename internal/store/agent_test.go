package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/agent"
	"github.com/xen0bit/netgraph/internal/policy"
)

func TestAgentBatch(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "ng.db"), Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	b := &agent.Batch{
		Version: agent.Version, Agent: "laptop", Boot: "boot1", Seq: 1,
		Hello:     &agent.Hello{Name: "laptop", Host: "laptop", OS: "linux", Capabilities: []string{"process-identity"}},
		Processes: []agent.Process{{PID: 42, PPID: 1, UID: 1000, Path: "/usr/bin/curl", Cmdline: "curl https://example.com", CodeID: "sha256:abcd"}},
		Connections: []agent.Connection{{
			Key: "tcp|10.0.0.2:50000|203.0.113.9:443", Proto: "tcp", LocalIP: "10.0.0.2", LocalPort: 50000,
			RemoteIP: "203.0.113.9", RemotePort: 443, Direction: "out", State: "ESTABLISHED", PID: 42,
			App: "curl", Predicted: "allow", Rule: "web",
		}},
	}
	if _, err := st.IngestAgentBatch(ctx, b); err != nil {
		t.Fatal(err)
	}
	agents, err := st.Agents(ctx)
	if err != nil || len(agents) != 1 || agents[0].Name != "laptop" || agents[0].Processes != 1 || agents[0].Connections != 1 {
		t.Fatalf("agents = %+v, %v", agents, err)
	}
	procs, err := st.AgentProcesses(ctx, "laptop", 10)
	if err != nil || len(procs) != 1 || procs[0].PID != 42 {
		t.Fatalf("processes = %+v, %v", procs, err)
	}
	conns, err := st.AgentConnections(ctx, "laptop", 10)
	if err != nil || len(conns) != 1 || conns[0].App != "curl" || conns[0].Predicted != "allow" {
		t.Fatalf("connections = %+v, %v", conns, err)
	}
	// A second batch updates the row and reports an actual result.
	if _, err := st.IngestAgentBatch(ctx, &agent.Batch{Version: agent.Version, Agent: "laptop", Boot: "boot1", Seq: 2,
		Actuals: []agent.Actual{{Key: "tcp|10.0.0.2:50000|203.0.113.9:443", Action: "deny", Rule: "web"}}}); err != nil {
		t.Fatal(err)
	}
	conns, _ = st.AgentConnections(ctx, "laptop", 10)
	if conns[0].Actual != "deny" {
		t.Fatalf("actual = %+v", conns[0])
	}
	// The active policy is what an agent asks for.
	if _, err := st.SavePolicy(ctx, &policy.Policy{Version: 2, Name: "agent", Defaults: policy.Defaults{Egress: "deny", Ingress: "deny", IntraZone: "allow", DNS: "allow"}, RulesV2: []policy.RuleV2{{Name: "x", Action: policy.ActionAllow, Local: policy.Selector{Type: "any"}, Remote: policy.Selector{Type: "any"}}}}); err != nil {
		t.Fatal(err)
	}
}

// Agent rows follow raw retention and db purge: every ephemeral port is a new
// connection row.
func TestAgentRowsAge(t *testing.T) {
	now := time.Now()
	st, err := Open(filepath.Join(t.TempDir(), "ng.db"), Config{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err := st.IngestAgentBatch(ctx, &agent.Batch{Version: agent.Version, Agent: "laptop",
		Processes:   []agent.Process{{PID: 7, Path: "/usr/bin/curl"}},
		Connections: []agent.Connection{{Key: "tcp|a|b", RemoteIP: "203.0.113.1"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.PurgeBefore(ctx, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	procs, _ := st.AgentProcesses(ctx, "laptop", 10)
	conns, _ := st.AgentConnections(ctx, "laptop", 10)
	if len(procs) != 0 || len(conns) != 0 {
		t.Fatalf("purge left %d processes, %d connections", len(procs), len(conns))
	}
}
