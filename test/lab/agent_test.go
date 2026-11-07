//go:build lab

package lab

import (
	"context"
	"testing"

	"github.com/xen0bit/netgraph/internal/apiclient"
	"github.com/xen0bit/netgraph/internal/graph"
	"github.com/xen0bit/netgraph/internal/model"
)

// checkAgent: netgraph-agent runs in the laptop's namespaces and reports its
// sockets; the server matches them to what the router's sensor saw, so the
// held connection is curl's, and the graph draws laptop ──runs──▶ curl
// ──connects──▶ hold.lab.test with the lookup folded in.
func checkAgent(t *testing.T, c *apiclient.Client, f model.Filter) {
	ctx := context.Background()
	agents, err := c.Agents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var a model.Agent
	for _, x := range agents {
		if x.Name == "lab-laptop-agent" {
			a = x
		}
	}
	if a.Name == "" || a.OS != "linux" || a.Connections == 0 || a.Processes == 0 {
		t.Fatalf("agents = %+v", agents)
	}
	fl, err := c.Flows(ctx, model.Filter{From: f.From, To: f.To, Domain: "hold.lab.test"})
	if err != nil || len(fl) != 1 {
		t.Fatalf("flows = %+v, %v", fl, err)
	}
	if h := fl[0]; h.Process != "curl" || h.Agent != "lab-laptop-agent" || h.PID == 0 {
		t.Errorf("held connection = %+v", h)
	}
	g, err := c.Graph(ctx, f, model.DefaultGraphOptions)
	if err != nil {
		t.Fatal(err)
	}
	dev := "device:" + laptopMAC
	curl := graph.ProcessID(dev, "curl")
	var runs, connects bool
	for _, e := range g.Edges {
		runs = runs || (e.From == dev && e.To == curl && e.Rel == model.RelRuns)
		connects = connects || (e.From == curl && e.To == "site:hold.lab.test" && e.Rel == model.RelConnects && e.Attrs["lookups"] != "")
	}
	if !runs || !connects {
		t.Errorf("graph lacks laptop -> curl -> hold.lab.test (runs %v, connects %v): %+v", runs, connects, g.Edges)
	}
	d, err := c.Entity(ctx, curl, f)
	if err != nil || d.Kind != model.KindProcess || len(d.Flows) == 0 || d.Attrs["code_id"] == "" {
		t.Errorf("curl's details = %+v, %v", d, err)
	}
}
