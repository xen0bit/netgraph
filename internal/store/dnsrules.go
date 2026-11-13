package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"

	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/policy/blocklist"
)

// DNSList is one enabled blocklist's enabled entries, for the DNS server.
type DNSList struct {
	Name    string
	Entries []blocklist.Entry
}

// DNSClient is what the DNS server knows of a client: the device that holds
// its address, and the groups a person put it in.
type DNSClient struct {
	MAC    string
	Groups []string
}

// dnsClientWindow is how recently a device must have held an address for the
// DNS server to apply its rules to lookups from it.
const dnsClientWindow = 7 * 24 * 60 * 60 * 1000

// DNSLists returns each enabled blocklist (in an enabled group, if any) with
// its enabled entries, in ID order.
func (s *Store) DNSLists(ctx context.Context) ([]DNSList, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT b.id, b.name, e.kind, e.value FROM blocklist_entries e
		JOIN blocklists b ON b.id = e.blocklist_id
		LEFT JOIN rule_groups g ON g.id = b.group_id
		WHERE e.enabled = 1 AND b.enabled = 1 AND (b.group_id IS NULL OR g.enabled = 1)
		ORDER BY b.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DNSList
	last := int64(-1)
	for rows.Next() {
		var id int64
		var name string
		var e blocklist.Entry
		if err := rows.Scan(&id, &name, &e.Kind, &e.Value); err != nil {
			return nil, err
		}
		if id != last {
			out = append(out, DNSList{Name: name})
			last = id
		}
		l := &out[len(out)-1]
		l.Entries = append(l.Entries, e)
	}
	return out, rows.Err()
}

// DNSRules lists the DNS server's rules, everyone's first.
func (s *Store) DNSRules(ctx context.Context) ([]model.DNSRule, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT id, auid, scope, scope_value, action, pattern, note, created, modified FROM dns_rules
		ORDER BY CASE scope WHEN 'all' THEN 0 WHEN 'group' THEN 1 ELSE 2 END, scope_value, pattern`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.DNSRule{}
	for rows.Next() {
		var r model.DNSRule
		if err := rows.Scan(&r.ID, &r.AUID, &r.Scope, &r.ScopeValue, &r.Action, &r.Pattern, &r.Note, &r.Created, &r.Modified); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// NormalizeDNSPattern reads a rule's pattern: a name, which covers its
// subdomains, written plain, as *.name or as AdGuard's ||name^; or * for
// every name.
func NormalizeDNSPattern(p string) (string, bool) {
	p = strings.ToLower(strings.TrimSpace(p))
	if p == "*" {
		return p, true
	}
	p = strings.TrimSuffix(strings.TrimPrefix(p, "||"), "^")
	p = strings.TrimPrefix(p, "*.")
	return blocklist.NormalizeName(p)
}

// SaveDNSRule adds a rule, or changes the one with r.ID. A rule for the same
// scope and pattern as another replaces it: a name is blocked or allowed, not
// both.
func (s *Store) SaveDNSRule(ctx context.Context, r *model.DNSRule) (*model.DNSRule, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: no rule", ErrInvalid)
	}
	in := *r
	pat, ok := NormalizeDNSPattern(in.Pattern)
	if !ok {
		return nil, fmt.Errorf("%w: %q is not a name", ErrInvalid, in.Pattern)
	}
	in.Pattern = pat
	if in.Scope == "" {
		in.Scope = model.DNSScopeAll
	}
	switch in.Scope {
	case model.DNSScopeAll:
		in.ScopeValue = ""
	case model.DNSScopeDevice:
		mac, ok := normMAC(strings.TrimSpace(strings.TrimPrefix(in.ScopeValue, "device:")))
		if !ok {
			return nil, fmt.Errorf("%w: a device rule needs the device's MAC", ErrInvalid)
		}
		in.ScopeValue = mac
	case model.DNSScopeGroup:
		in.ScopeValue = strings.TrimSpace(in.ScopeValue)
		if in.ScopeValue == "" || len(in.ScopeValue) > 64 || strings.Contains(in.ScopeValue, ",") {
			return nil, fmt.Errorf("%w: a group rule needs the group's name", ErrInvalid)
		}
	default:
		return nil, fmt.Errorf("%w: scope must be all, device or group", ErrInvalid)
	}
	if in.Action != model.DNSBlock && in.Action != model.DNSAllow {
		return nil, fmt.Errorf("%w: action must be block or allow", ErrInvalid)
	}
	if in.Pattern == "*" && in.Action == model.DNSBlock {
		return nil, fmt.Errorf("%w: blocking every name would stop every lookup; allow * turns filtering off instead", ErrInvalid)
	}
	in.Note = clip(strings.TrimSpace(in.Note), 500)
	now := s.cfg.Now().UnixMilli()
	s.mu.Lock()
	defer s.mu.Unlock()
	var id int64
	if in.ID != 0 {
		res, err := s.w.ExecContext(ctx, `UPDATE dns_rules SET scope = ?, scope_value = ?, action = ?, pattern = ?, note = ?, modified = ? WHERE id = ?`,
			in.Scope, in.ScopeValue, in.Action, in.Pattern, in.Note, now, in.ID)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				return nil, fmt.Errorf("%w: there is already a rule for %s here", ErrInvalid, in.Pattern)
			}
			return nil, err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return nil, ErrNotFound
		}
		id = in.ID
	} else {
		auid, err := newPolicyID("dns_")
		if err != nil {
			return nil, err
		}
		if err := s.w.QueryRowContext(ctx, `INSERT INTO dns_rules (auid, scope, scope_value, action, pattern, note, created, modified)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (scope, scope_value, pattern) DO UPDATE SET action = excluded.action, note = excluded.note, modified = excluded.modified
			RETURNING id`, auid, in.Scope, in.ScopeValue, in.Action, in.Pattern, in.Note, now, now).Scan(&id); err != nil {
			return nil, err
		}
	}
	var out model.DNSRule
	err := s.w.QueryRowContext(ctx, `SELECT id, auid, scope, scope_value, action, pattern, note, created, modified FROM dns_rules WHERE id = ?`, id).
		Scan(&out.ID, &out.AUID, &out.Scope, &out.ScopeValue, &out.Action, &out.Pattern, &out.Note, &out.Created, &out.Modified)
	return &out, err
}

// DeleteDNSRule removes a rule.
func (s *Store) DeleteDNSRule(ctx context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.w.ExecContext(ctx, `DELETE FROM dns_rules WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DNSClients maps each address a device held in the last week to that device:
// the newest holder, when an address changed hands.
func (s *Store) DNSClients(ctx context.Context) (map[netip.Addr]DNSClient, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT ip.key, d.key, d.attrs, max(f.last_seen) FROM facts f
		JOIN entities d ON d.id = f.src AND d.kind = 'device'
		JOIN entities ip ON ip.id = f.dst AND ip.kind = 'ip'
		WHERE f.rel = ? AND f.last_seen >= ? GROUP BY ip.key`, model.RelHasIP, s.cfg.Now().UnixMilli()-dnsClientWindow)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[netip.Addr]DNSClient{}
	for rows.Next() {
		var ip, mac, attrs string
		var last int64
		if err := rows.Scan(&ip, &mac, &attrs, &last); err != nil {
			return nil, err
		}
		a, err := netip.ParseAddr(ip)
		if err != nil {
			continue
		}
		c := DNSClient{MAC: mac}
		if g := attrValue(attrs, "groups"); g != "" {
			c.Groups = strings.Split(g, ",")
		}
		out[a.Unmap()] = c
	}
	return out, rows.Err()
}

// DNSFingerprint changes whenever what the DNS server blocks might have: a
// list, an entry, a rule or a device's groups. It is cheap to ask every few
// seconds; rebuilding the rules is not.
func (s *Store) DNSFingerprint(ctx context.Context) (string, error) {
	// Only the small tables: an entry turned off bumps its list's modified.
	var lists, entries, rules, groups sql.NullString
	err := s.r.QueryRowContext(ctx, `SELECT
		(SELECT count(*) || ':' || coalesce(sum(modified), 0) || ':' || coalesce(sum(last_success), 0) || ':' || coalesce(sum(enabled), 0) FROM blocklists),
		(SELECT coalesce(sum(entry_count), 0) FROM blocklists),
		(SELECT count(*) || ':' || coalesce(max(modified), 0) || ':' || coalesce(sum(id), 0) FROM dns_rules),
		(SELECT count(*) || ':' || coalesce(sum(enabled), 0) || ':' || coalesce(sum(modified), 0) FROM rule_groups)`).
		Scan(&lists, &entries, &rules, &groups)
	if err != nil {
		return "", err
	}
	return strings.Join([]string{lists.String, entries.String, rules.String, groups.String}, "|"), nil
}

// attrValue reads one key of an entity's attrs JSON without decoding all of it.
func attrValue(attrs, key string) string {
	var a map[string]string
	if err := json.Unmarshal([]byte(attrs), &a); err != nil {
		return ""
	}
	return a[key]
}

// DNSStats counts lookups and refusals in the window: the DNS server's own,
// and any other source that reports blocking (an AdGuard Home or Pi-hole log).
func (s *Store) DNSStats(ctx context.Context, f model.Filter) (*model.DNSStats, error) {
	from, to := s.window(f)
	if to <= from {
		return nil, fmt.Errorf("%w: from must be before to", ErrInvalid)
	}
	out := &model.DNSStats{FromMS: from, ToMS: to, Precision: s.precision(from, to), Series: []model.DNSStatsPoint{},
		TopBlocked: []model.DNSNameCount{}, TopAsked: []model.DNSNameCount{}, Clients: []model.DNSClientStat{}}
	step := max((to-from)/60, 60_000)
	var table, count, ts string
	var w *where
	var err error
	if out.Precision == model.PrecisionExact {
		w, err = s.dnsWhere(ctx, f, from, to)
		table, count, ts = "dns", "1", "ts"
	} else {
		w, err = s.dnsHourlyWhere(ctx, f, from, to)
		table, count, ts = "dns_hourly", "count", "bucket"
		step = max(step-step%3_600_000, 3_600_000)
	}
	if err != nil {
		return nil, err
	}
	step -= step % 60_000
	out.StepMS = step
	blocked := fmt.Sprintf("CASE WHEN rcode = '%s' THEN %s ELSE 0 END", rcodeBlocked, count)
	cond := w.sql()
	if err := s.r.QueryRowContext(ctx, `SELECT coalesce(sum(`+count+`), 0), coalesce(sum(`+blocked+`), 0) FROM `+table+` WHERE `+cond, w.args...).
		Scan(&out.Queries, &out.Blocked); err != nil {
		return nil, err
	}
	rows, err := s.r.QueryContext(ctx, `SELECT `+ts+` - (`+ts+` % ?) AS b, sum(`+count+`), sum(`+blocked+`) FROM `+table+` WHERE `+cond+` GROUP BY b ORDER BY b`,
		append([]any{step}, w.args...)...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var p model.DNSStatsPoint
		if err := rows.Scan(&p.TS, &p.Queries, &p.Blocked); err != nil {
			rows.Close()
			return nil, err
		}
		out.Series = append(out.Series, p)
	}
	rows.Close()
	names := func(extra string, dst *[]model.DNSNameCount) error {
		rows, err := s.r.QueryContext(ctx, `SELECT lower(qname), sum(`+count+`) AS n FROM `+table+` WHERE `+cond+extra+` AND qname != '' GROUP BY 1 ORDER BY n DESC, 1 LIMIT 20`, w.args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c model.DNSNameCount
			if err := rows.Scan(&c.Name, &c.Count); err != nil {
				return err
			}
			*dst = append(*dst, c)
		}
		return rows.Err()
	}
	if err := names(fmt.Sprintf(" AND rcode = '%s'", rcodeBlocked), &out.TopBlocked); err != nil {
		return nil, err
	}
	if err := names("", &out.TopAsked); err != nil {
		return nil, err
	}
	rows, err = s.r.QueryContext(ctx, `SELECT client_device, CASE WHEN client_device = 0 THEN client_ip ELSE '' END AS ip,
		sum(`+count+`) AS n, sum(`+blocked+`) FROM `+table+` WHERE `+cond+` GROUP BY 1, 2 ORDER BY n DESC LIMIT 20`, w.args...)
	if err != nil {
		return nil, err
	}
	var devs []int64
	for rows.Next() {
		var c model.DNSClientStat
		var dev int64
		if err := rows.Scan(&dev, &c.ClientIP, &c.Queries, &c.Blocked); err != nil {
			rows.Close()
			return nil, err
		}
		if dev != 0 {
			c.Device = fmt.Sprint(dev) // resolved below
			devs = append(devs, dev)
		}
		out.Clients = append(out.Clients, c)
	}
	rows.Close()
	if len(devs) > 0 {
		names, err := s.deviceNames(ctx, devs)
		if err != nil {
			return nil, err
		}
		for i := range out.Clients {
			if out.Clients[i].Device == "" {
				continue
			}
			var id int64
			_, _ = fmt.Sscan(out.Clients[i].Device, &id)
			n := names[id]
			out.Clients[i].Device, out.Clients[i].DeviceName = model.EntityID(model.KindDevice, n.mac), n.label
		}
	}
	return out, nil
}

type deviceName struct{ mac, label string }

// deviceNames reads device entities' MACs and display names.
func (s *Store) deviceNames(ctx context.Context, ids []int64) (map[int64]deviceName, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT id, key, label, attrs FROM entities WHERE kind = 'device' AND id IN (`+idList(ids)+`)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]deviceName{}
	for rows.Next() {
		var id int64
		var mac, label, attrs string
		if err := rows.Scan(&id, &mac, &label, &attrs); err != nil {
			return nil, err
		}
		var a map[string]string
		_ = json.Unmarshal([]byte(attrs), &a)
		out[id] = deviceName{mac, deviceLabel(mac, label, a)}
	}
	return out, rows.Err()
}

// rcodeBlocked marks a refused lookup (sources.RCodeBlocked; the store can't
// import sources).
const rcodeBlocked = "BLOCKED"
