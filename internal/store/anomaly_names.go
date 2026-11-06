package store

import (
	"context"
	"fmt"
	"strings"

	"github.com/xen0bit/netgraph/internal/model"
)

// nameMismatches finds connections whose SNI/HTTP host was never resolved by
// the same device, and names sharing an address with a different observed
// name. It is evidence, not a verdict: CDNs and hard-coded addresses do this.
func (a *anomalies) nameMismatches(ctx context.Context) error {
	rows, err := a.s.r.QueryContext(ctx, `SELECT c.client_device, e.key, c.remote_ip, c.sni, c.http_host, c.first_seen
		FROM connections c LEFT JOIN entities e ON e.id = c.client_device
		WHERE c.first_seen >= ? AND c.first_seen < ? AND (c.sni != '' OR c.http_host != '')
		ORDER BY c.first_seen DESC LIMIT 500`, a.from, a.to)
	if err != nil {
		return err
	}
	type item struct {
		device, mac, ip, sni, host string
		ts                         int64
	}
	var items []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.device, &it.mac, &it.ip, &it.sni, &it.host, &it.ts); err != nil {
			rows.Close()
			return err
		}
		items = append(items, it)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, it := range items {
		name := strings.TrimSuffix(firstNonEmpty(it.sni, it.host), ".")
		if name == "" || strings.EqualFold(name, it.ip) {
			continue
		}
		key := it.device + "|" + strings.ToLower(name)
		if seen[key] {
			continue
		}
		seen[key] = true
		var n int
		if err := a.s.r.QueryRowContext(ctx, `SELECT count(*) FROM dns
			WHERE client_ip = ? AND lower(qname) = lower(?) AND ts <= ?`, it.ip, name, it.ts+60_000).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			continue
		}
		var other string
		_ = a.s.r.QueryRowContext(ctx, `SELECT qname FROM dns_answers WHERE data = ? AND lower(qname) != lower(?)
			AND expires >= ? LIMIT 1`, it.ip, name, it.ts).Scan(&other)
		why := "the device did not resolve this name"
		if other != "" {
			why = fmt.Sprintf("the address also carries %q", other)
		}
		a.add(model.Anomaly{
			Kind: model.AnomalyNameMismatch, Severity: model.SeverityMedium, TS: it.ts,
			Device: it.device, DeviceName: firstNonEmpty(it.mac, it.device), Entity: model.EntityID(model.KindDomain, strings.ToLower(name)),
			Summary:  fmt.Sprintf("%s asked for %q; %s", firstNonEmpty(it.mac, "a device"), name, why),
			Evidence: map[string]string{"name": name, "ip": it.ip, "sni": it.sni, "http_host": it.host, "why": why},
		})
	}
	return nil
}
