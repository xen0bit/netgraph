package store

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/policy"
	"github.com/xen0bit/netgraph/internal/policy/blocklist"
)

// WhatIf evaluates a proposed policy against the traffic observed in a
// window. It is read-only and deliberately conservative: unclassified
// traffic is reported as unknown, never silently blocked.
func (s *Store) WhatIf(ctx context.Context, p *policy.Policy, f model.Filter, scope string) (*model.WhatIfResult, error) {
	if err := f.ApplyScope(scope); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	from, to := s.window(f)
	out := &model.WhatIfResult{FromMS: from, ToMS: to, PolicyHash: p.Hash()}
	ff := f
	if ff.Limit <= 0 || ff.Limit > 20000 {
		ff.Limit = 20000
	}
	flows, err := s.Flows(ctx, ff)
	if err != nil {
		return nil, err
	}
	if len(flows) >= ff.Limit {
		out.Gaps = append(out.Gaps, fmt.Sprintf("flow list was capped at %d; the blast radius may be larger", ff.Limit))
	}
	devices, err := s.Devices(ctx, ff)
	if err != nil {
		return nil, err
	}
	type info struct{ label, role string }
	byID := map[string]info{}
	routers := map[string]bool{}
	for _, d := range devices {
		byID[d.ID] = info{label: d.Label, role: d.Role}
		if d.Role == "router" {
			for _, ip := range d.IPs {
				routers[ip] = true
			}
		}
	}
	matcher, err := s.BlocklistMatcher(ctx)
	if err != nil {
		return nil, err
	}
	activeProfile, err := s.ActiveProfile(ctx)
	if err != nil {
		return nil, err
	}
	profileName := ""
	if activeProfile != nil {
		profileName = activeProfile.Name
	}
	blocked := map[string]*model.ImpactGroup{}
	destGroups := map[string]*model.ImpactGroup{}
	ruleGroups := map[string]*model.ImpactGroup{}
	addGroup := func(m map[string]*model.ImpactGroup, key, label string, imp *model.Impact) {
		if key == "" {
			key, label = "unknown", "unknown"
		}
		g := m[key]
		if g == nil {
			g = &model.ImpactGroup{Key: key, Label: label}
			m[key] = g
		}
		g.Connections++
		g.BytesOut += imp.BytesOut
		g.BytesIn += imp.BytesIn
	}
	add := func(imp model.Impact, essential bool) {
		if imp.Kind == "dns" {
			out.Summary.Lookups++
		} else {
			out.Summary.Blocked++
		}
		if essential {
			out.Summary.Essential++
			out.Essential = append(out.Essential, imp)
		} else {
			out.Blocked = append(out.Blocked, imp)
		}
		devKey := imp.Device
		if devKey == "" {
			devKey = imp.DeviceName
		}
		addGroup(blocked, devKey, imp.DeviceName, &imp)
		addGroup(destGroups, imp.Destination, imp.Destination, &imp)
		ruleKey := imp.Rule
		if ruleKey == "" {
			ruleKey = "default " + imp.Direction
		}
		addGroup(ruleGroups, ruleKey, ruleKey, &imp)
	}
	for i, fl := range flows {
		if i%1024 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		if fl.Direction == model.DirExternal {
			out.Summary.OutOfScope++
			continue
		}
		dev := byID[fl.Device]
		zone := p.ZoneFor(fl.Device, firstNonEmpty(fl.DeviceName, dev.label, fl.Device), dev.role)
		dst := firstNonEmpty(fl.Name, fl.RemoteIP)
		// Version 1 rules only select zones; version 2 rules can select a
		// device, its label or anything, so a device without a zone is still
		// decided there.
		if zone == "" && p.Version != 2 {
			imp := model.Impact{
				Kind: "connection", Device: fl.Device, DeviceName: firstNonEmpty(fl.DeviceName, dev.label),
				Destination: dst, Port: portString(fl), Direction: fl.Direction,
				BytesOut: fl.BytesOut, BytesIn: fl.BytesIn, Connections: 1,
				Reason: "device is not assigned to a zone", Evidence: []model.EvidenceRef{{Kind: "flow", ID: fl.Key, TS: fl.FirstSeen, Text: dst}},
			}
			out.Unknown = append(out.Unknown, imp)
			out.Summary.Unknown++
			continue
		}
		peerZone := ""
		if fl.PeerDevice != "" {
			peer := byID[fl.PeerDevice]
			peerZone = p.ZoneFor(fl.PeerDevice, firstNonEmpty(fl.PeerName, peer.label, fl.PeerDevice), peer.role)
		}
		decision := p.Evaluate(policy.Conn{
			Zone: zone, PeerZone: peerZone, Device: fl.Device, Label: firstNonEmpty(fl.DeviceName, dev.label),
			Role: dev.role, Direction: fl.Direction, Profile: profileName, Name: dst, Host: fl.Name, QName: fl.QName,
			IP: fl.RemoteIP, Port: strconv.Itoa(servicePort(fl)), Proto: fl.Proto,
			ASN: fl.ASN, Country: fl.Country,
		})
		// A blocklist denies what a device here reaches out to, unless a person
		// wrote a high or extra-high allow for it: that is how an exception to
		// a list is made. It never decides inbound connections.
		if e, ok := blocklisted(matcher, fl.Direction, dst, fl.RemoteIP); ok && !overridesBlocklist(decision) {
			imp := model.Impact{
				Kind: "connection", Device: fl.Device, DeviceName: firstNonEmpty(fl.DeviceName, dev.label),
				Zone: zone, Destination: dst, Port: portString(fl), Direction: fl.Direction,
				BytesOut: fl.BytesOut, BytesIn: fl.BytesIn, Connections: 1,
				Rule: "blocklist", Reason: "blocked by blocklist entry " + e.Value,
				Critical: criticalFlow(fl, routers, dst),
				Evidence: []model.EvidenceRef{{Kind: "flow", ID: fl.Key, TS: fl.FirstSeen, Text: dst}},
			}
			add(imp, imp.Critical)
			continue
		}
		if decision.Action == policy.ActionAsk {
			imp := model.Impact{
				Kind: "connection", Device: fl.Device, DeviceName: firstNonEmpty(fl.DeviceName, dev.label),
				Zone: zone, Destination: dst, Port: portString(fl), Direction: fl.Direction,
				BytesOut: fl.BytesOut, BytesIn: fl.BytesIn, Connections: 1, Rule: decision.Rule,
				Reason:   "would ask by rule " + decision.Rule,
				Evidence: []model.EvidenceRef{{Kind: "flow", ID: fl.Key, TS: fl.FirstSeen, Text: dst}},
			}
			out.WouldAsk = append(out.WouldAsk, imp)
			out.Summary.WouldAsk++
			continue
		}
		if decision.Action != policy.ActionDeny {
			out.Summary.Unchanged++
			continue
		}
		rule := decision.Rule
		reason := "denied by default"
		if rule != "" {
			reason = "denied by rule " + rule
		}
		imp := model.Impact{
			Kind: "connection", Device: fl.Device, DeviceName: firstNonEmpty(fl.DeviceName, dev.label),
			Zone: zone, Destination: dst, Port: portString(fl), Direction: fl.Direction,
			BytesOut: fl.BytesOut, BytesIn: fl.BytesIn, Connections: 1, Rule: rule, Reason: reason,
			Critical: criticalFlow(fl, routers, dst),
			Evidence: []model.EvidenceRef{{Kind: "flow", ID: fl.Key, TS: fl.FirstSeen, Text: dst}},
		}
		add(imp, imp.Critical)
	}
	// DNS is a dependency of its own: a lookup can be blocked even when a
	// cached address still works, or allowed while the address rule fails.
	// Blocking a name is usually the point of the rule, so it is not
	// essential by itself; losing port 53 outright is, and is a connection.
	dns, err := s.DNS(ctx, ff)
	if err != nil {
		return nil, err
	}
	if len(dns) >= ff.Limit {
		out.Gaps = append(out.Gaps, fmt.Sprintf("lookup list was capped at %d; more names may be blocked", ff.Limit))
	}
	for _, q := range dns {
		blocked := p.DNSBlocked(q.QName)
		if !blocked && matcher != nil {
			_, blocked = matcher.MatchName(q.QName)
		}
		if !blocked {
			continue
		}
		add(model.Impact{
			Kind: "dns", Device: q.Device, DeviceName: q.DeviceName, Destination: q.QName,
			Reason:   "DNS blocklist",
			Evidence: []model.EvidenceRef{{Kind: "dns", ID: fmt.Sprintf("%d:%s:%s", q.TS, q.QName, q.ClientIP), TS: q.TS, Text: q.QName}},
		}, false)
	}
	sortImpacts := func(xs []model.Impact) {
		slices.SortFunc(xs, func(a, b model.Impact) int {
			return cmp.Or(
				cmp.Compare(b.BytesOut+b.BytesIn, a.BytesOut+a.BytesIn),
				cmp.Compare(a.DeviceName, b.DeviceName),
				cmp.Compare(a.Destination, b.Destination),
				cmp.Compare(a.Port, b.Port),
			)
		})
	}
	sortImpacts(out.Blocked)
	sortImpacts(out.Essential)
	sortImpacts(out.Unknown)
	groups := func(m map[string]*model.ImpactGroup) []model.ImpactGroup {
		out := make([]model.ImpactGroup, 0, len(m))
		for _, g := range m {
			out = append(out, *g)
		}
		slices.SortFunc(out, func(a, b model.ImpactGroup) int {
			return cmp.Or(cmp.Compare(b.BytesOut+b.BytesIn, a.BytesOut+a.BytesIn), cmp.Compare(a.Key, b.Key))
		})
		return out
	}
	out.ByDevice = groups(blocked)
	out.ByDestination = groups(destGroups)
	out.ByRule = groups(ruleGroups)
	out.Summary.Connections = len(flows)
	out.Gaps = append(out.Gaps,
		"the simulation uses observed traffic only; traffic that never happened is invisible",
		"blocked probes, unicast DHCP and encrypted DNS are not visible",
	)
	if s.precision(from, to) != model.PrecisionExact {
		out.Gaps = append(out.Gaps, "the window is answered from hourly rollups")
	}
	return out, nil
}

// blocklisted reports the entry that blocks a connection a device here made.
func blocklisted(m *blocklist.Matcher, direction, name, ip string) (blocklist.Entry, bool) {
	if m == nil || direction == model.DirIn {
		return blocklist.Entry{}, false
	}
	if e, ok := m.MatchName(name); ok {
		return e, true
	}
	return m.MatchIP(ip)
}

// overridesBlocklist: an allow a person ranked above regular wins over a list.
func overridesBlocklist(d policy.Decision) bool {
	return d.Matched && d.Action == policy.ActionAllow &&
		(d.Priority == policy.PriorityHigh || d.Priority == policy.PriorityExtraHigh)
}

func portString(fl model.Flow) string {
	return strconv.Itoa(servicePort(fl)) + "/" + fl.Proto
}

func servicePort(fl model.Flow) int {
	if fl.Direction == model.DirIn {
		return fl.ServerPort
	}
	return fl.RemotePort
}

func criticalFlow(fl model.Flow, routers map[string]bool, dst string) bool {
	switch servicePort(fl) {
	case 53, 67, 68, 123:
		return true
	}
	if routers[fl.RemoteIP] {
		return true
	}
	return strings.EqualFold(dst, "gateway")
}
