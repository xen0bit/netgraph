package store

import (
	"cmp"
	"context"
	"slices"
	"strconv"

	"github.com/xen0bit/netgraph/internal/graph"
	"github.com/xen0bit/netgraph/internal/model"
)

// ConnectionGroups folds observed flows into the dimensions the monitor uses:
// device, app, site/domain, host or destination. It is read-only and uses the
// same window and filters as Flows.
func (s *Store) ConnectionGroups(ctx context.Context, f model.Filter, group string) ([]model.ConnectionGroup, error) {
	if group == "" {
		group = "domain"
	}
	switch group {
	case "device", "app", "domain", "host", "destination", "remote":
	default:
		return nil, ErrInvalid
	}
	ff := f
	if ff.Limit <= 0 || ff.Limit > 50000 {
		ff.Limit = 50000
	}
	flows, err := s.Flows(ctx, ff)
	if err != nil {
		return nil, err
	}
	by := map[string]*model.ConnectionGroup{}
	for _, fl := range flows {
		key, kind, label := groupKey(fl, group)
		if key == "" {
			key, kind, label = "unknown", group, "unknown"
		}
		g := by[key]
		if g == nil {
			g = &model.ConnectionGroup{Key: key, Kind: kind, Label: label}
			by[key] = g
		}
		g.Connections++
		g.BytesOut += fl.BytesOut
		g.BytesIn += fl.BytesIn
		if g.FirstSeen == 0 || fl.FirstSeen < g.FirstSeen {
			g.FirstSeen = fl.FirstSeen
		}
		if fl.LastSeen > g.LastSeen {
			g.LastSeen = fl.LastSeen
		}
		g.Devices = appendUnique(g.Devices, fl.Device)
		g.DeviceNames = appendUnique(g.DeviceNames, firstNonEmpty(fl.DeviceName, fl.Device))
		g.Destinations = appendUnique(g.Destinations, firstNonEmpty(fl.Name, fl.RemoteIP))
		g.Ports = appendUnique(g.Ports, strconv.Itoa(servicePort(fl))+"/"+fl.Proto)
		g.RemoteIPs = appendUnique(g.RemoteIPs, fl.RemoteIP)
		g.Names = appendUnique(g.Names, fl.Name)
	}
	out := make([]model.ConnectionGroup, 0, len(by))
	for _, g := range by {
		slices.Sort(g.Devices)
		slices.Sort(g.DeviceNames)
		slices.Sort(g.Destinations)
		slices.Sort(g.Ports)
		slices.Sort(g.RemoteIPs)
		slices.Sort(g.Names)
		out = append(out, *g)
	}
	slices.SortFunc(out, func(a, b model.ConnectionGroup) int {
		return cmp.Or(cmp.Compare(b.BytesOut+b.BytesIn, a.BytesOut+a.BytesIn), cmp.Compare(a.Key, b.Key))
	})
	return out, nil
}

func groupKey(fl model.Flow, group string) (key, kind, label string) {
	switch group {
	case "device":
		return fl.Device, "device", firstNonEmpty(fl.DeviceName, fl.Device)
	case "app":
		return firstNonEmpty(fl.App, "unknown"), "app", firstNonEmpty(fl.App, "unknown")
	case "domain":
		name := firstNonEmpty(fl.Name, fl.RemoteIP)
		if site := graph.Site(name); site != "" {
			return site, "domain", site
		}
		return name, "destination", name
	case "host":
		name := firstNonEmpty(fl.Name, fl.RemoteIP)
		return name, "host", name
	case "destination":
		name := firstNonEmpty(fl.Name, fl.RemoteIP)
		return name, "destination", name
	case "remote":
		return fl.RemoteIP, "remote", fl.RemoteIP
	}
	return "", group, ""
}

func appendUnique(xs []string, v string) []string {
	if v == "" {
		return xs
	}
	if slices.Contains(xs, v) {
		return xs
	}
	return append(xs, v)
}
