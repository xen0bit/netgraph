package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/xen0bit/netgraph/internal/model"
)

// nameMismatches finds connections whose SNI/HTTP host the same device never
// looked up, while the sensor did see that device's lookups. It is evidence,
// not a verdict: a hard-coded address or a long-cached answer does this too,
// so it is low severity. A device whose lookups the sensor never sees (DNS
// over HTTPS, or a resolver on another path) is skipped: every one of its
// connections would match.
func (a *anomalies) nameMismatches(ctx context.Context) error {
	rows, err := a.s.r.QueryContext(ctx, `SELECT c.client_device, e.key, c.remote_ip, c.sni, c.http_host, c.first_seen
		FROM connections c JOIN entities e ON e.id = c.client_device AND e.kind = 'device'
		WHERE c.first_seen >= ? AND c.first_seen < ? AND (c.sni != '' OR c.http_host != '')
		ORDER BY c.first_seen DESC LIMIT 500`, a.from, a.to)
	if err != nil {
		return err
	}
	type item struct {
		dev       int64
		mac, ip   string
		sni, host string
		ts        int64
	}
	var items []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.dev, &it.mac, &it.ip, &it.sni, &it.host, &it.ts); err != nil {
			rows.Close()
			return err
		}
		items = append(items, it)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	resolves := map[int64]bool{}
	seen := map[string]bool{}
	for _, it := range items {
		name := strings.ToLower(strings.TrimSuffix(firstNonEmpty(it.sni, it.host), "."))
		if name == "" || strings.EqualFold(name, it.ip) {
			continue
		}
		if _, err := netip.ParseAddr(name); err == nil {
			continue // a Host header holding an address names nothing
		}
		key := strconv.FormatInt(it.dev, 10) + "|" + name
		if seen[key] {
			continue
		}
		seen[key] = true
		looks, ok := resolves[it.dev]
		if !ok {
			var n int
			if err := a.s.r.QueryRowContext(ctx, `SELECT count(*) FROM (SELECT 1 FROM dns WHERE client_device = ? AND ts <= ? LIMIT 1)`, it.dev, a.to).Scan(&n); err != nil {
				return err
			}
			looks = n > 0
			resolves[it.dev] = looks
		}
		if !looks {
			continue
		}
		var n int
		if err := a.s.r.QueryRowContext(ctx, `SELECT count(*) FROM (SELECT 1 FROM dns
			WHERE lower(qname) = ? AND client_device = ? AND ts <= ? LIMIT 1)`, name, it.dev, it.ts+60_000).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			continue
		}
		var other string
		err := a.s.r.QueryRowContext(ctx, `SELECT qname FROM dns_answers WHERE data = ? AND lower(qname) != ? AND expires >= ? LIMIT 1`,
			it.ip, name, it.ts).Scan(&other)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		why := "the device did not look this name up"
		if other != "" {
			why += fmt.Sprintf("; the address answered for %q", other)
		}
		devs, err := a.devices(ctx, []int64{it.dev})
		if err != nil {
			return err
		}
		d := devs[it.dev]
		if d == nil {
			continue
		}
		a.add(model.Anomaly{
			Kind: model.AnomalyNameMismatch, Severity: model.SeverityLow, TS: it.ts,
			Device: d.id, DeviceName: d.name, Entity: model.EntityID(model.KindDomain, name),
			Summary:  fmt.Sprintf("%s connected to %q without looking it up", d.name, name),
			Evidence: map[string]string{"name": name, "ip": it.ip, "sni": it.sni, "http_host": it.host, "why": why},
		})
	}
	return nil
}
