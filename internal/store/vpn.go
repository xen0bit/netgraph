package store

// VPN sessions from netgraph-edge, and the attribution of flows to them.
//
// An edge reports each session on its listeners as it opens and closes: the
// identity the protocol's handshake proved, and the inner prefixes the
// session held. Its flows carry no MAC (a tunnel has none), so a flow is
// attributed by address and time instead: to the session, on the same edge,
// that held the flow's client address when the flow began. That is evidence,
// not a guess -- the server assigned or checked that address after
// authenticating the peer -- which is why it is only ever done for flows from
// the edge that reported the session.

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/netip"
	"strings"
	"time"

	"github.com/xen0bit/netgraph/internal/wire"
)

// maxVPNSessionsCached bounds one edge's cached sessions: IDs, users and
// prefixes come from the edge, which is trusted, but not unboundedly.
const maxVPNSessionsCached = 1 << 16

// vpnSessionSlack is how long a closed session stays in the cache: a flow
// record arrives up to MaxRecordSpan after the interval it reports began,
// and its session may have closed in between.
const vpnSessionSlack = 2 * MaxRecordSpan

type vpnSess struct {
	id       int64
	prefixes []netip.Prefix
	start    int64
	end      int64 // 0 while open
}

type vpnCache struct {
	byKey map[vpnKey]*vpnSess // the edge's (boot, listener, session) -> row
}

type vpnKey struct {
	boot, listener string
	session        uint64
}

// vpnFor returns sid's cached sessions, loading them on first use. A sensor
// that has never reported a session costs one query per ingester lifetime.
func (g *ingester) vpnFor(ctx context.Context, sid int64, now int64) (*vpnCache, error) {
	if g.vpn == nil {
		g.vpn = map[int64]*vpnCache{}
	}
	if c, ok := g.vpn[sid]; ok {
		return c, nil
	}
	c := &vpnCache{byKey: map[vpnKey]*vpnSess{}}
	rows, err := g.tx.QueryContext(ctx, `SELECT id, boot, listener, session, prefixes, t_start, coalesce(t_end, 0)
		FROM vpn_sessions WHERE sensor_id = ? AND (t_end IS NULL OR t_end >= ?)
		ORDER BY t_start DESC LIMIT ?`, sid, now-vpnSessionSlack.Milliseconds(), maxVPNSessionsCached)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var s vpnSess
		var k vpnKey
		var prefixes string
		if err := rows.Scan(&s.id, &k.boot, &k.listener, &k.session, &prefixes, &s.start, &s.end); err != nil {
			return nil, err
		}
		s.prefixes = parsePrefixList(prefixes)
		c.byKey[k] = &s
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	g.vpn[sid] = c
	return c, nil
}

func parsePrefixList(s string) []netip.Prefix {
	var out []netip.Prefix
	_ = json.Unmarshal([]byte(s), &out)
	return out
}

// vpnSession records an edge's session opening or closing.
func (g *ingester) vpnSession(ctx context.Context, sid int64, boot string, ts int64, v *wire.VPNSession) error {
	if v.ID == 0 || v.Listener == "" {
		return nil
	}
	c, err := g.vpnFor(ctx, sid, ts)
	if err != nil {
		return err
	}
	k := vpnKey{boot: boot, listener: v.Listener, session: v.ID}
	if !v.Open {
		s := c.byKey[k]
		if s == nil {
			// The open was never seen (lost, or from before this database):
			// with no start there is no interval to attribute anything to.
			return nil
		}
		end := max(ts, s.start)
		if _, err := g.tx.ExecContext(ctx, `UPDATE vpn_sessions SET t_end = ?, reason = ? WHERE id = ? AND t_end IS NULL`,
			end, v.Reason, s.id); err != nil {
			return err
		}
		s.end = end
		g.pruneVPN(c, ts)
		return nil
	}
	if c.byKey[k] != nil {
		return nil // a replayed open: the shipper retries whole batches
	}
	prefixes := make([]netip.Prefix, 0, len(v.Addrs))
	for _, p := range v.Addrs {
		if p.IsValid() && len(prefixes) < 64 {
			prefixes = append(prefixes, p.Masked())
		}
	}
	pj, _ := json.Marshal(prefixes)
	outer := ""
	if v.Outer.IsValid() {
		outer = v.Outer.String()
	}
	var id int64
	err = g.tx.QueryRowContext(ctx, `INSERT INTO vpn_sessions
		(sensor_id, boot, listener, session, protocol, user, auth, name, prefixes, outer, t_start)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (sensor_id, boot, listener, session) DO UPDATE SET protocol = excluded.protocol
		RETURNING id`,
		sid, boot, v.Listener, v.ID, v.Protocol, truncate(v.User, 512), truncate(v.Auth, 32), truncate(v.Name, 256), string(pj), outer, ts).Scan(&id)
	if err != nil {
		return err
	}
	if len(c.byKey) < maxVPNSessionsCached {
		c.byKey[k] = &vpnSess{id: id, prefixes: prefixes, start: ts}
	}
	return nil
}

// pruneVPN drops sessions that closed long enough ago that no flow can still
// arrive for them.
func (g *ingester) pruneVPN(c *vpnCache, now int64) {
	cut := now - vpnSessionSlack.Milliseconds()
	for k, s := range c.byKey {
		if s.end != 0 && s.end < cut {
			delete(c.byKey, k)
		}
	}
}

// vpnSessionFor returns the session on sid that held addr at time t (ms), or
// 0. Windows are half-open: a session holds its prefixes in [start, end). When
// two overlap, as a reassigned address briefly can across a missed close, the
// later one wins.
func (g *ingester) vpnSessionFor(ctx context.Context, sid int64, addr netip.Addr, t int64) (int64, error) {
	c, err := g.vpnFor(ctx, sid, t)
	if err != nil || len(c.byKey) == 0 {
		return 0, err
	}
	var best *vpnSess
	for _, s := range c.byKey {
		if s.start > t || (s.end != 0 && t >= s.end) {
			continue
		}
		if best != nil && s.start <= best.start {
			continue
		}
		for _, p := range s.prefixes {
			if p.Contains(addr) {
				best = s
				break
			}
		}
	}
	if best == nil {
		return 0, nil
	}
	return best.id, nil
}

// truncate cuts s to at most n bytes without splitting a character.
func truncate(s string, n int) string {
	if len(s) > n {
		return strings.ToValidUTF8(s[:n], "")
	}
	return s
}

// VPNSession is one session an edge reported, for the API.
type VPNSession struct {
	ID       int64      `json:"id"`
	Sensor   string     `json:"sensor"`
	Listener string     `json:"listener"`
	Protocol string     `json:"protocol"`
	User     string     `json:"user"`
	Auth     string     `json:"auth,omitempty"`
	Name     string     `json:"name,omitempty"`
	Prefixes []string   `json:"prefixes"`
	Outer    string     `json:"outer,omitempty"`
	Start    time.Time  `json:"start"`
	End      *time.Time `json:"end,omitempty"`
	Reason   string     `json:"reason,omitempty"`
	Flows    int64      `json:"flows"`
	BytesOut int64      `json:"bytes_out"`
	BytesIn  int64      `json:"bytes_in"`
}

// VPNSessions returns the sessions that overlap [from, to), newest first, with
// the traffic of the connections attributed to each.
func (s *Store) VPNSessions(ctx context.Context, from, to time.Time, limit int) ([]VPNSession, error) {
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	rows, err := s.r.QueryContext(ctx, `SELECT v.id, se.name, v.listener, v.protocol, v.user, v.auth, v.name, v.prefixes, v.outer,
			v.t_start, v.t_end, v.reason,
			(SELECT count(*) FROM connections c WHERE c.vpn_session = v.id),
			(SELECT coalesce(sum(c.bytes_out), 0) FROM connections c WHERE c.vpn_session = v.id),
			(SELECT coalesce(sum(c.bytes_in), 0) FROM connections c WHERE c.vpn_session = v.id)
		FROM vpn_sessions v JOIN sensors se ON se.id = v.sensor_id
		WHERE v.t_start < ? AND (v.t_end IS NULL OR v.t_end >= ?)
		ORDER BY v.t_start DESC LIMIT ?`, to.UnixMilli(), from.UnixMilli(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VPNSession
	for rows.Next() {
		var v VPNSession
		var prefixes string
		var start int64
		var end sql.NullInt64
		if err := rows.Scan(&v.ID, &v.Sensor, &v.Listener, &v.Protocol, &v.User, &v.Auth, &v.Name, &prefixes, &v.Outer,
			&start, &end, &v.Reason, &v.Flows, &v.BytesOut, &v.BytesIn); err != nil {
			return nil, err
		}
		v.Start = time.UnixMilli(start).UTC()
		if end.Valid {
			e := time.UnixMilli(end.Int64).UTC()
			v.End = &e
		}
		v.Prefixes = []string{}
		for _, p := range parsePrefixList(prefixes) {
			v.Prefixes = append(v.Prefixes, p.String())
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
