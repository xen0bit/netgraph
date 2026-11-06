package store

import (
	"context"
	"fmt"

	"github.com/xen0bit/netgraph/internal/backup"
	"github.com/xen0bit/netgraph/internal/policy/blocklist"
	"github.com/xen0bit/netgraph/internal/purpose"
)

// ExportBundle gathers configuration, not observations. Decisions, tokens and
// keys are deliberately absent.
func (s *Store) ExportBundle(ctx context.Context) (*backup.Bundle, error) {
	b := backup.New()
	list, err := s.Policies(ctx)
	if err != nil {
		return nil, err
	}
	for _, sum := range list {
		p, err := s.Policy(ctx, sum.ID)
		if err != nil {
			return nil, err
		}
		b.Policies = append(b.Policies, p)
	}
	if b.Profiles, err = s.Profiles(ctx); err != nil {
		return nil, err
	}
	if b.Triggers, err = s.NetworkTriggers(ctx); err != nil {
		return nil, err
	}
	lists, err := s.Blocklists(ctx)
	if err != nil {
		return nil, err
	}
	for _, l := range lists {
		entries, err := s.BlocklistEntries(ctx, l.ID, false, 500000, 0)
		if err != nil {
			return nil, err
		}
		b.Blocklists = append(b.Blocklists, backup.BlocklistBundle{List: l, Entries: entries})
	}
	if b.Purposes, err = s.Purposes(ctx); err != nil {
		return nil, err
	}
	return b, nil
}

// ImportBundle restores configuration. It is additive/replacing by AUID and
// never touches traffic history.
func (s *Store) ImportBundle(ctx context.Context, b *backup.Bundle) (map[string]int, error) {
	if b == nil {
		return nil, fmt.Errorf("%w: no bundle", ErrInvalid)
	}
	if err := b.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	counts := map[string]int{}
	for _, p := range b.Policies {
		if _, err := s.SavePolicy(ctx, p); err != nil {
			return counts, fmt.Errorf("policy %q: %w", p.Name, err)
		}
		counts["policies"]++
	}
	for i := range b.Profiles {
		if _, err := s.SaveProfile(ctx, &b.Profiles[i]); err != nil {
			return counts, fmt.Errorf("profile %q: %w", b.Profiles[i].Name, err)
		}
		counts["profiles"]++
	}
	for i := range b.Triggers {
		if _, err := s.SaveNetworkTrigger(ctx, &b.Triggers[i]); err != nil {
			return counts, fmt.Errorf("trigger %q: %w", b.Triggers[i].Signature, err)
		}
		counts["triggers"]++
	}
	for _, lb := range b.Blocklists {
		saved, err := s.SaveBlocklist(ctx, &lb.List)
		if err != nil {
			return counts, fmt.Errorf("blocklist %q: %w", lb.List.Name, err)
		}
		parsed := &blocklist.Parsed{Entries: make([]blocklist.Entry, 0, len(lb.Entries))}
		for _, e := range lb.Entries {
			parsed.Entries = append(parsed.Entries, blocklist.Entry{Kind: e.Kind, Value: e.Value})
		}
		if err := s.ReplaceBlocklistEntries(ctx, saved.ID, parsed); err != nil {
			return counts, err
		}
		counts["blocklists"]++
	}
	byApp := map[string]*purpose.Manifest{}
	for _, p := range b.Purposes {
		m := byApp[p.Application]
		if m == nil {
			m = &purpose.Manifest{Application: p.Application, Developer: p.Developer, Website: p.Website, Source: p.Source}
			byApp[p.Application] = m
		}
		m.Connections = append(m.Connections, purpose.Connection{Host: p.Host, Purpose: p.Purpose, DenyConsequences: p.DenyConsequences})
	}
	for _, m := range byApp {
		n, err := s.ImportPurpose(ctx, m)
		if err != nil {
			return counts, err
		}
		counts["purposes"] += n
	}
	return counts, nil
}
