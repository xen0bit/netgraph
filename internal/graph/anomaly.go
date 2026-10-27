package graph

import (
	"slices"
	"strings"

	"github.com/xen0bit/netgraph/internal/model"
)

// MarkAnomalies marks the nodes and edges that medium and high anomalies
// are about: the device, what it reached (its site or address, however the
// graph draws it), and the edge between them. A marked node or edge gets
// attrs "anomaly" (the highest severity) and "anomalies" (their summaries,
// one per line). Low anomalies stay in the list: drawn, they would colour
// half a busy graph.
func MarkAnomalies(g *model.Graph, as []model.Anomaly) {
	byID := map[string]*model.Node{}
	for i := range g.Nodes {
		byID[g.Nodes[i].ID] = &g.Nodes[i]
	}
	mark := func(attrs *map[string]string, a model.Anomaly) {
		if *attrs == nil {
			*attrs = map[string]string{}
		}
		m := *attrs
		if model.SeverityRank(a.Severity) > model.SeverityRank(m["anomaly"]) {
			m["anomaly"] = a.Severity
		}
		if lines := strings.Split(m["anomalies"], "\n"); !slices.Contains(lines, a.Summary) {
			m["anomalies"] = strings.TrimPrefix(m["anomalies"]+"\n"+a.Summary, "\n")
		}
	}
	for _, a := range as {
		if model.SeverityRank(a.Severity) < model.SeverityRank(model.SeverityMedium) {
			continue
		}
		var targets []string
		if n := byID[a.Device]; n != nil {
			mark(&n.Attrs, a)
		}
		if a.Entity != "" {
			for i := range g.Nodes {
				if n := &g.Nodes[i]; about(n, a.Entity) {
					mark(&n.Attrs, a)
					targets = append(targets, n.ID)
				}
			}
		}
		for i := range g.Edges {
			e := &g.Edges[i]
			if e.From == a.Device && slices.Contains(targets, e.To) {
				mark(&e.Attrs, a)
			}
		}
	}
}

// about reports whether node n stands for entity id: the same node, a name
// under the same site, or a name node listing the address.
func about(n *model.Node, id string) bool {
	if n.ID == id {
		return true
	}
	kind, key, _ := model.SplitEntityID(id)
	switch kind {
	case model.KindSite:
		switch n.Kind {
		case model.KindDomain:
			return Site(n.Label) == key
		case model.KindSite:
			_, site, _ := model.SplitEntityID(n.ID)
			return site == key
		}
	case model.KindIP:
		if n.Kind == model.KindDomain || n.Kind == model.KindSite {
			return slices.Contains(strings.Split(n.Attrs["addresses"], ","), key)
		}
	}
	return false
}
