package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/policy/blocklist"
)

// RuleGroups lists blocklist groups.
func (s *Store) RuleGroups(ctx context.Context) ([]model.RuleGroup, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT id, auid, name, description, type, url, enabled, update_interval,
		last_success, last_failure, last_error, invalid_entries, created, modified FROM rule_groups ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.RuleGroup{}
	for rows.Next() {
		var g model.RuleGroup
		var enabled int
		if err := rows.Scan(&g.ID, &g.AUID, &g.Name, &g.Description, &g.Type, &g.URL, &enabled, &g.UpdateInterval,
			&g.LastSuccess, &g.LastFailure, &g.LastError, &g.InvalidEntries, &g.Created, &g.Modified); err != nil {
			return nil, err
		}
		g.Enabled = enabled != 0
		out = append(out, g)
	}
	return out, rows.Err()
}

// SaveRuleGroup inserts a group, or updates the fields a person sets on one
// (by AUID). Update bookkeeping is the server's and is never taken from the caller.
func (s *Store) SaveRuleGroup(ctx context.Context, g *model.RuleGroup) (*model.RuleGroup, error) {
	g.Name = strings.TrimSpace(g.Name)
	if g.Name == "" {
		return nil, fmt.Errorf("%w: a group needs a name", ErrInvalid)
	}
	if g.Type == "" {
		g.Type = "local"
	}
	if g.Type != "local" && g.Type != "remote" && g.Type != "factory" {
		return nil, fmt.Errorf("%w: group type %q", ErrInvalid, g.Type)
	}
	if err := checkFeedURL(g.URL); err != nil {
		return nil, err
	}
	if g.AUID == "" {
		id, err := newPolicyID("grp_")
		if err != nil {
			return nil, err
		}
		g.AUID = id
	}
	now := s.cfg.Now().UTC().UnixMilli()
	if g.UpdateInterval <= 0 {
		g.UpdateInterval = 86400
	}
	s.mu.Lock()
	_, err := s.w.ExecContext(ctx, `INSERT INTO rule_groups
		(auid, name, description, type, url, enabled, update_interval, created, modified)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(auid) DO UPDATE SET name=excluded.name, description=excluded.description, type=excluded.type,
		url=excluded.url, enabled=excluded.enabled, update_interval=excluded.update_interval, modified=excluded.modified`,
		g.AUID, g.Name, g.Description, g.Type, g.URL, boolInt(g.Enabled), g.UpdateInterval, now, now)
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	groups, err := s.RuleGroups(ctx)
	if err != nil {
		return nil, err
	}
	for i := range groups {
		if groups[i].AUID == g.AUID {
			return &groups[i], nil
		}
	}
	return nil, fmt.Errorf("%w: group %s", ErrNotFound, g.AUID)
}

// checkFeedURL accepts an empty URL (a list filled by import) or an https one.
// Whether the address is public is checked when it is fetched.
func checkFeedURL(raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("%w: feed URL must be an http(s) URL", ErrInvalid)
	}
	return nil
}

// Blocklists lists blocklists, newest first.
func (s *Store) Blocklists(ctx context.Context) ([]model.Blocklist, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT id, auid, coalesce(group_id, 0), name, url, format, enabled,
		update_interval, last_success, last_failure, last_error, etag, last_modified, entry_count, invalid_entries, created, modified
		FROM blocklists ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Blocklist{}
	for rows.Next() {
		var b model.Blocklist
		var enabled int
		if err := rows.Scan(&b.ID, &b.AUID, &b.GroupID, &b.Name, &b.URL, &b.Format, &enabled,
			&b.UpdateInterval, &b.LastSuccess, &b.LastFailure, &b.LastError, &b.ETag, &b.LastModified,
			&b.EntryCount, &b.InvalidEntries, &b.Created, &b.Modified); err != nil {
			return nil, err
		}
		b.Enabled = enabled != 0
		out = append(out, b)
	}
	return out, rows.Err()
}

// Blocklist loads one blocklist by integer ID.
func (s *Store) Blocklist(ctx context.Context, id int64) (*model.Blocklist, error) {
	var b model.Blocklist
	var enabled int
	err := s.r.QueryRowContext(ctx, `SELECT id, auid, coalesce(group_id, 0), name, url, format, enabled,
		update_interval, last_success, last_failure, last_error, etag, last_modified, entry_count, invalid_entries, created, modified
		FROM blocklists WHERE id = ?`, id).
		Scan(&b.ID, &b.AUID, &b.GroupID, &b.Name, &b.URL, &b.Format, &enabled, &b.UpdateInterval,
			&b.LastSuccess, &b.LastFailure, &b.LastError, &b.ETag, &b.LastModified, &b.EntryCount, &b.InvalidEntries, &b.Created, &b.Modified)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: blocklist %d", ErrNotFound, id)
	}
	if err != nil {
		return nil, err
	}
	b.Enabled = enabled != 0
	return &b, nil
}

// SaveBlocklist inserts a blocklist, or updates the fields a person sets on
// one: name, URL, format, group, enabled and update interval. It is found by
// AUID, else by ID, which must then exist. Fetch state and counts are the
// server's and are never taken from the caller.
func (s *Store) SaveBlocklist(ctx context.Context, b *model.Blocklist) (*model.Blocklist, error) {
	b.Name = strings.TrimSpace(b.Name)
	if b.Name == "" {
		return nil, fmt.Errorf("%w: a blocklist needs a name", ErrInvalid)
	}
	if b.Format == "" {
		b.Format = blocklist.FormatAuto
	}
	switch b.Format {
	case blocklist.FormatAuto, blocklist.FormatHosts, blocklist.FormatDomains, blocklist.FormatIPs, blocklist.FormatLSRules:
	default:
		return nil, fmt.Errorf("%w: format %q", ErrInvalid, b.Format)
	}
	if err := checkFeedURL(b.URL); err != nil {
		return nil, err
	}
	if b.UpdateInterval <= 0 {
		b.UpdateInterval = 86400
	}
	if b.GroupID > 0 {
		var one int
		if err := s.r.QueryRowContext(ctx, `SELECT 1 FROM rule_groups WHERE id = ?`, b.GroupID).Scan(&one); err != nil {
			return nil, fmt.Errorf("%w: group %d", ErrNotFound, b.GroupID)
		}
	}
	if b.AUID == "" && b.ID != 0 {
		existing, err := s.Blocklist(ctx, b.ID)
		if err != nil {
			return nil, err
		}
		b.AUID = existing.AUID
	}
	if b.AUID == "" {
		id, err := newPolicyID("bl_")
		if err != nil {
			return nil, err
		}
		b.AUID = id
	}
	now := s.cfg.Now().UTC().UnixMilli()
	s.mu.Lock()
	_, err := s.w.ExecContext(ctx, `INSERT INTO blocklists
		(auid, group_id, name, url, format, enabled, update_interval, created, modified)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(auid) DO UPDATE SET group_id=excluded.group_id, name=excluded.name, url=excluded.url,
		format=excluded.format, enabled=excluded.enabled, update_interval=excluded.update_interval,
		modified=excluded.modified`,
		b.AUID, nullableID(b.GroupID), b.Name, b.URL, b.Format, boolInt(b.Enabled), b.UpdateInterval, now, now)
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return s.blocklistByAUID(ctx, b.AUID)
}

func nullableID(id int64) any {
	if id <= 0 {
		return nil
	}
	return id
}

func (s *Store) blocklistByAUID(ctx context.Context, auid string) (*model.Blocklist, error) {
	var id int64
	if err := s.r.QueryRowContext(ctx, `SELECT id FROM blocklists WHERE auid = ?`, auid).Scan(&id); err != nil {
		return nil, err
	}
	return s.Blocklist(ctx, id)
}

// DeleteBlocklist removes a blocklist and its entries.
func (s *Store) DeleteBlocklist(ctx context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM blocklist_entries WHERE blocklist_id = ?`, id); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM blocklists WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: blocklist %d", ErrNotFound, id)
	}
	return tx.Commit()
}

// BlocklistEntries lists entries, optionally only enabled ones.
func (s *Store) BlocklistEntries(ctx context.Context, id int64, enabledOnly bool, limit, offset int) ([]model.BlocklistEntry, error) {
	if limit <= 0 || limit > 500000 {
		limit = 5000
	}
	q := `SELECT id, blocklist_id, kind, value, enabled, unapproved, use_count, last_used, notes
		FROM blocklist_entries WHERE blocklist_id = ?`
	if enabledOnly {
		q += ` AND enabled = 1`
	}
	q += ` ORDER BY kind, value LIMIT ? OFFSET ?`
	rows, err := s.r.QueryContext(ctx, q, id, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.BlocklistEntry{}
	for rows.Next() {
		var e model.BlocklistEntry
		var enabled, unapproved int
		if err := rows.Scan(&e.ID, &e.Blocklist, &e.Kind, &e.Value, &enabled, &unapproved, &e.UseCount, &e.LastUsed, &e.Notes); err != nil {
			return nil, err
		}
		e.Enabled, e.Unapproved = enabled != 0, unapproved != 0
		out = append(out, e)
	}
	return out, rows.Err()
}

// SetBlocklistEntry enables or disables one entry.
func (s *Store) SetBlocklistEntry(ctx context.Context, blocklistID, entryID int64, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.w.ExecContext(ctx, `UPDATE blocklist_entries SET enabled = ? WHERE id = ? AND blocklist_id = ?`,
		boolInt(enabled), entryID, blocklistID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: entry %d", ErrNotFound, entryID)
	}
	return nil
}

// ReplaceBlocklistEntries swaps a blocklist's parsed entries while preserving
// per-entry enable state and usage for values that are still present.
func (s *Store) ReplaceBlocklistEntries(ctx context.Context, id int64, parsed *blocklist.Parsed) error {
	if parsed == nil {
		return fmt.Errorf("%w: no parsed blocklist", ErrInvalid)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var one int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM blocklists WHERE id = ?`, id).Scan(&one); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: blocklist %d", ErrNotFound, id)
		}
		return err
	}
	type state struct {
		enabled    bool
		unapproved bool
		useCount   int64
		lastUsed   int64
		notes      string
	}
	old := map[string]state{}
	rows, err := tx.QueryContext(ctx, `SELECT kind, value, enabled, unapproved, use_count, last_used, notes FROM blocklist_entries WHERE blocklist_id = ?`, id)
	if err != nil {
		return err
	}
	for rows.Next() {
		var k, v, notes string
		var en, un int
		var uc, lu int64
		if err := rows.Scan(&k, &v, &en, &un, &uc, &lu, &notes); err != nil {
			rows.Close()
			return err
		}
		old[k+"\x00"+v] = state{en != 0, un != 0, uc, lu, notes}
	}
	rows.Close()
	if _, err := tx.ExecContext(ctx, `DELETE FROM blocklist_entries WHERE blocklist_id = ?`, id); err != nil {
		return err
	}
	now := s.cfg.Now().UTC().UnixMilli()
	seen := map[string]bool{}
	for _, e := range parsed.Entries {
		key := e.Kind + "\x00" + e.Value
		if seen[key] {
			continue
		}
		seen[key] = true
		st, ok := old[key]
		en, un, uc, lu, notes := true, false, int64(0), int64(0), ""
		if ok {
			en, un, uc, lu, notes = st.enabled, st.unapproved, st.useCount, st.lastUsed, st.notes
		} else if e.Disabled {
			en = false // a restored entry someone had turned off stays off
		}
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO blocklist_entries
			(blocklist_id, kind, value, enabled, unapproved, use_count, last_used, notes)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, id, e.Kind, e.Value, boolInt(en), boolInt(un), uc, lu, notes); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE blocklists SET entry_count = ?, invalid_entries = ?, last_success = ?, last_error = '', modified = ? WHERE id = ?`,
		len(seen), parsed.Invalid, now, now, id); err != nil {
		return err
	}
	return tx.Commit()
}

// BlocklistMatcher builds a matcher from all enabled entries in enabled
// blocklists and groups. It is a snapshot: refresh it after an update.
func (s *Store) BlocklistMatcher(ctx context.Context) (*blocklist.Matcher, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT e.kind, e.value FROM blocklist_entries e
		JOIN blocklists b ON b.id = e.blocklist_id
		LEFT JOIN rule_groups g ON g.id = b.group_id
		WHERE e.enabled = 1 AND b.enabled = 1 AND (b.group_id IS NULL OR g.enabled = 1)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := blocklist.New(nil)
	for rows.Next() {
		var e blocklist.Entry
		if err := rows.Scan(&e.Kind, &e.Value); err != nil {
			return nil, err
		}
		m.Add(e)
	}
	return m, rows.Err()
}

// UpdateBlocklist fetches a blocklist URL, parses it and replaces its entries.
// A 304 keeps the entries and only records the success time.
func (s *Store) UpdateBlocklist(ctx context.Context, id int64, f *blocklist.Fetcher) (*model.Blocklist, error) {
	b, err := s.Blocklist(ctx, id)
	if err != nil {
		return nil, err
	}
	if b.URL == "" {
		return nil, fmt.Errorf("%w: blocklist %d has no URL", ErrInvalid, id)
	}
	if f == nil {
		f = &blocklist.Fetcher{}
	}
	res, err := f.Fetch(ctx, b.URL, b.ETag, b.LastModified)
	now := s.cfg.Now().UTC().UnixMilli()
	if err != nil {
		s.mu.Lock()
		_, _ = s.w.ExecContext(ctx, `UPDATE blocklists SET last_failure = ?, last_error = ?, modified = ? WHERE id = ?`, now, err.Error(), now, id)
		s.mu.Unlock()
		return nil, err
	}
	if res.NotModified {
		s.mu.Lock()
		_, err = s.w.ExecContext(ctx, `UPDATE blocklists SET last_success = ?, last_error = '', etag = ?, last_modified = ?, modified = ? WHERE id = ?`,
			now, res.ETag, res.LastModified, now, id)
		s.mu.Unlock()
		if err != nil {
			return nil, err
		}
		return s.Blocklist(ctx, id)
	}
	parsed, err := blocklist.Parse(strings.NewReader(string(res.Body)), b.Format)
	if err != nil {
		s.mu.Lock()
		_, _ = s.w.ExecContext(ctx, `UPDATE blocklists SET last_failure = ?, last_error = ?, modified = ? WHERE id = ?`, now, err.Error(), now, id)
		s.mu.Unlock()
		return nil, err
	}
	if err := s.ReplaceBlocklistEntries(ctx, id, parsed); err != nil {
		return nil, err
	}
	s.mu.Lock()
	_, err = s.w.ExecContext(ctx, `UPDATE blocklists SET etag = ?, last_modified = ?, last_success = ?, last_error = '', modified = ? WHERE id = ?`,
		res.ETag, res.LastModified, now, now, id)
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return s.Blocklist(ctx, id)
}
