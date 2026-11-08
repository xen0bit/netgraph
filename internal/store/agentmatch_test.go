package store

import (
	"context"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/agent"
	"github.com/xen0bit/netgraph/internal/graph"
	"github.com/xen0bit/netgraph/internal/model"
)

// A host agent on the web server names the programs behind the sensor's
// connections: nginx accepted the visitor, python3 called the API. A socket
// with the same addresses an hour away is another connection.
func TestAgentNamesFlowProcesses(t *testing.T) {
	ctx := context.Background()
	st, at := inboundStore(t, Config{})
	ms := func(d time.Duration) int64 { return at.Add(d).UnixMilli() }
	if _, err := st.IngestAgentBatch(ctx, &agent.Batch{Version: agent.Version, Agent: "web-agent", Boot: "b", Seq: 1,
		Connections: []agent.Connection{
			{Key: "in", Proto: "tcp6", LocalIP: webIP.String(), LocalPort: 443, RemoteIP: visitor.String(), RemotePort: 51234,
				Direction: "in", PID: 80, App: "nginx", Path: "/usr/sbin/nginx", CodeID: "sha256:aa", FirstSeen: ms(5 * time.Second), LastSeen: ms(5 * time.Second)},
			{Key: "out", Proto: "tcp", LocalIP: webIP.String(), LocalPort: 40001, RemoteIP: upstream.String(), RemotePort: 443,
				Direction: "out", PID: 99, App: "python3", FirstSeen: ms(10 * time.Second), LastSeen: ms(70 * time.Second)},
			// python3's socket again after it closed, in TIME_WAIT, as agents
			// up to 0.1.9 sent it: no program, and seen later. It must not
			// shadow the sighting that named python3.
			{Key: "out|0", Proto: "tcp", LocalIP: webIP.String(), LocalPort: 40001, RemoteIP: upstream.String(), RemotePort: 443,
				Direction: "out", State: "TIME_WAIT", FirstSeen: ms(80 * time.Second), LastSeen: ms(140 * time.Second)},
			// The scanner's tuple, but long before it connected.
			{Key: "old", Proto: "tcp", LocalIP: webIP.String(), LocalPort: 80, RemoteIP: scanner.String(), RemotePort: 40000,
				App: "old-httpd", FirstSeen: ms(-time.Hour), LastSeen: ms(-time.Hour + time.Minute)},
		}}); err != nil {
		t.Fatal(err)
	}
	win := model.Filter{From: at, To: at.Add(time.Hour)}
	flows, err := st.Flows(ctx, win)
	if err != nil {
		t.Fatal(err)
	}
	got := map[int]model.Flow{}
	for _, fl := range flows {
		got[fl.RemotePort] = fl
	}
	if fl := got[51234]; fl.Process != "nginx" || fl.PID != 80 || fl.Agent != "web-agent" {
		t.Errorf("inbound flow = %+v", fl)
	}
	if fl := got[443]; fl.Process != "python3" || fl.PID != 99 {
		t.Errorf("outbound flow = %+v", fl)
	}
	if fl := got[40000]; fl.Process != "" {
		t.Errorf("an old socket named the scanner's connection: %+v", fl)
	}

	dev := model.EntityID(model.KindDevice, webMAC)
	g, err := st.Graph(ctx, win, model.DefaultGraphOptions)
	if err != nil {
		t.Fatal(err)
	}
	nodes := map[string]model.Node{}
	for _, n := range g.Nodes {
		nodes[n.ID] = n
	}
	edges := map[[3]string]model.Edge{}
	for _, e := range g.Edges {
		edges[[3]string{e.From, e.To, e.Rel}] = e
	}
	nginx, py := graph.ProcessID(dev, "nginx"), graph.ProcessID(dev, "python3")
	if n := nodes[nginx]; n.Kind != model.KindProcess || n.Label != "nginx" || n.Attrs["agent"] != "web-agent" || n.Attrs["device"] != dev {
		t.Fatalf("nginx node = %+v", n)
	}
	if nodes[dev].Attrs["agent"] != "web-agent" {
		t.Errorf("device node = %+v", nodes[dev])
	}
	if e, ok := edges[[3]string{dev, py, model.RelRuns}]; !ok || e.BytesOut != 300 || e.BytesIn != 4000 {
		t.Errorf("runs edge = %+v (%v)", e, ok)
	}
	// The API call hangs off python3, not the device.
	for k := range edges {
		if k[0] == dev && k[2] == model.RelConnects {
			if n := nodes[k[1]]; n.Kind == model.KindDomain && n.Label == "api.example.com" {
				t.Errorf("the device still connects to the API directly")
			}
		}
	}
	// The device keeps its totals with or without processes drawn.
	plain := model.DefaultGraphOptions
	plain.Processes = false
	g2, err := st.Graph(ctx, win, plain)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range g2.Nodes {
		if n.Kind == model.KindProcess {
			t.Fatalf("process drawn with Processes off: %+v", n)
		}
		if n.ID == dev && (n.BytesOut != nodes[dev].BytesOut || n.BytesIn != nodes[dev].BytesIn) {
			t.Errorf("device totals %d/%d, with processes %d/%d", n.BytesOut, n.BytesIn, nodes[dev].BytesOut, nodes[dev].BytesIn)
		}
	}

	d, err := st.Entity(ctx, nginx, win)
	if err != nil {
		t.Fatal(err)
	}
	if d.Kind != model.KindProcess || d.Label != "nginx" || len(d.Flows) != 1 || d.Attrs["path"] != "/usr/sbin/nginx" || d.Attrs["pids"] != "80" {
		t.Fatalf("process entity = %+v", d)
	}
	if _, err := st.Entity(ctx, graph.ProcessID(dev, "nothing"), win); err == nil {
		t.Fatal("a process with no connections was found")
	}
}

// A program's details say what each PID ran and who started it, from the
// processes the agent described; a bare PID never blanks what was known,
// and a reused PID is a new process.
func TestAgentProcessLineage(t *testing.T) {
	ctx := context.Background()
	st, at := inboundStore(t, Config{})
	ms := func(d time.Duration) int64 { return at.Add(d).UnixMilli() }
	send := func(seq uint64, procs []agent.Process, conns []agent.Connection) {
		t.Helper()
		if _, err := st.IngestAgentBatch(ctx, &agent.Batch{Version: agent.Version, Agent: "web-agent", Boot: "b", Seq: seq,
			Processes: procs, Connections: conns}); err != nil {
			t.Fatal(err)
		}
	}
	send(1, []agent.Process{
		{PID: 10, PPID: 1, Path: "/usr/sbin/sshd", Cmdline: "sshd", Start: 1000},
		{PID: 20, PPID: 10, Path: "/usr/bin/bash", Cmdline: "bash", Start: 2000},
		{PID: 99, PPID: 20, Path: "/usr/bin/python3.12", Cmdline: "python3 job.py", Start: 3000},
	}, []agent.Connection{{Key: "out", Proto: "tcp", LocalIP: webIP.String(), LocalPort: 40001, RemoteIP: upstream.String(), RemotePort: 443,
		Direction: "out", PID: 99, App: "python3.12", FirstSeen: ms(10 * time.Second), LastSeen: ms(70 * time.Second)}})
	// An older agent's bare PID for bash: ignored.
	send(2, []agent.Process{{PID: 20}}, nil)
	win := model.Filter{From: at, To: at.Add(time.Hour)}
	dev := model.EntityID(model.KindDevice, webMAC)
	d, err := st.Entity(ctx, graph.ProcessID(dev, "python3.12"), win)
	if err != nil {
		t.Fatal(err)
	}
	if d.Attrs["cmdline"] != "pid 99: python3 job.py" || d.Attrs["started by"] != "sshd (10) › bash (20)" {
		t.Fatalf("lineage = %q / %q", d.Attrs["cmdline"], d.Attrs["started by"])
	}
	var first int64
	read := func() {
		t.Helper()
		if err := st.r.QueryRowContext(ctx, `SELECT first_seen FROM agent_processes WHERE agent='web-agent' AND pid=20`).Scan(&first); err != nil {
			t.Fatal(err)
		}
	}
	read()
	was := first
	st.cfg.Now = func() time.Time { return time.UnixMilli(was).Add(time.Hour) }
	send(3, []agent.Process{{PID: 20, PPID: 10, Path: "/usr/bin/bash", Cmdline: "bash", Start: 2000}}, nil)
	if read(); first != was {
		t.Fatalf("same process: first_seen moved from %d to %d", was, first)
	}
	send(4, []agent.Process{{PID: 20, PPID: 1, Path: "/usr/bin/sleep", Cmdline: "sleep", Start: 9000}}, nil)
	if read(); first == was {
		t.Fatal("a reused PID kept the old process's first_seen")
	}
}
