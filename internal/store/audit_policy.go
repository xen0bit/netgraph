package store

import (
	"context"

	"github.com/xen0bit/netgraph/internal/policy"
	"github.com/xen0bit/netgraph/internal/policy/blocklist"
)

type blocklistAuditAdapter struct{ m *blocklist.Matcher }

func (a blocklistAuditAdapter) MatchName(name string) (string, bool) {
	e, ok := a.m.MatchName(name)
	return e.Value, ok
}

func (a blocklistAuditAdapter) MatchIP(ip string) (string, bool) {
	e, ok := a.m.MatchIP(ip)
	return e.Value, ok
}

// AuditPolicy runs the conservative policy audit against the current
// profiles and blocklists.
func (s *Store) AuditPolicy(ctx context.Context, p *policy.Policy) (*policy.AuditReport, error) {
	if p == nil {
		return policy.Audit(&policy.Policy{Version: 2}, nil, nil), nil
	}
	profiles, err := s.Profiles(ctx)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(profiles))
	for _, pr := range profiles {
		names = append(names, pr.Name)
	}
	m, err := s.BlocklistMatcher(ctx)
	if err != nil {
		return nil, err
	}
	return policy.Audit(p, names, blocklistAuditAdapter{m: m}), nil
}
