package store

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/testutil"
)

// openAt creates a database migrated only up to version v, for testing the
// migrations after it.
func openAt(t *testing.T, path string, v int) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", dsn(path, false))
	if err != nil {
		t.Fatal(err)
	}
	entries, err := migrations.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries[:v] {
		body, err := migrations.ReadFile("migrations/" + e.Name())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(string(body)); err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
	}
	if _, err := db.Exec(fmt.Sprintf("PRAGMA user_version = %d", v)); err != nil {
		t.Fatal(err)
	}
	return db
}

// Before version 6, an inbound connection was counted from its initiator's
// side and credited the initiator's fingerprint and user agent to the
// device, and the name it asked for to the initiator's address.
func TestMigrateInbound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ng.db")
	db := openAt(t, path, 5)
	ts := testutil.Base.UnixMilli()
	for _, q := range []string{
		`INSERT INTO entities (id, kind, key, first_seen, last_seen) VALUES
			(1, 'device', '02:42:ac:12:00:03', 0, 0), (2, 'ip', '198.51.100.7', 0, 0), (3, 'domain', 'web.example.com', 0, 0),
			(4, 'fingerprint', 'ja4:t13d_visitor', 0, 0), (5, 'useragent', 'zgrab/0.x', 0, 0),
			(6, 'ip', '93.184.215.14', 0, 0), (7, 'domain', 'api.example.com', 0, 0), (8, 'fingerprint', 'ja4:t13d_server', 0, 0)`,
		`INSERT INTO facts (rel, src, dst, first_seen, last_seen, source) VALUES
			('serves', 2, 3, 0, 0, 'sni'), ('fingerprint', 1, 4, 0, 0, 'tls'), ('user_agent', 1, 5, 0, 0, 'http'),
			('serves', 6, 7, 0, 0, 'sni'), ('fingerprint', 1, 8, 0, 0, 'tls')`,
		`INSERT INTO connections (flow_key, sensor_id, proto, client_ip, client_port, client_device, remote_ip, remote_port, direction,
			first_seen, last_seen, sni, ja4, user_agent, qname, bytes_out, bytes_in, pkts_out, pkts_in) VALUES
			('in', 1, 6, '172.18.0.3', 443, 1, '198.51.100.7', 51234, 'in', ?1, ?1, 'web.example.com', 't13d_visitor', 'zgrab/0.x', 'stale', 1000, 50000, 10, 40),
			('out', 1, 6, '172.18.0.3', 40001, 1, '93.184.215.14', 443, 'out', ?1, ?1, 'api.example.com', 't13d_server', '', '', 300, 4000, 3, 5)`,
		`INSERT INTO flows (sensor_id, flow_key, proto, src_ip, src_port, dst_ip, dst_port, first_seen, t_start, t_end,
			bytes_out, bytes_in, pkts_out, pkts_in, client_ip, client_port, client_device, remote_ip, remote_port, direction) VALUES
			(1, 'in', 6, '198.51.100.7', 51234, '172.18.0.3', 443, ?1, ?1, ?1, 1000, 50000, 10, 40, '172.18.0.3', 443, 1, '198.51.100.7', 51234, 'in')`,
		`INSERT INTO traffic_hourly (bucket, client_device, client_ip, remote_ip, remote_port, proto, name, app, multicast, flows, bytes_out, bytes_in) VALUES
			(0, 1, '172.18.0.3', '198.51.100.7', 51234, 6, 'web.example.com', 'tls', 0, 1, 1000, 50000),
			(0, 1, '172.18.0.3', '93.184.215.14', 443, 6, 'api.example.com', 'tls', 0, 1, 300, 4000),
			(-3600000, 1, '172.18.0.3', '192.0.2.1', 22, 6, '', '', 0, 1, 5, 6)`,
	} {
		if _, err := db.Exec(q, ts); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	db.Close()

	st, err := Open(path, Config{Now: func() time.Time { return testutil.Base }})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	check := func(q string, want ...any) {
		t.Helper()
		row := st.r.QueryRow(q)
		got := make([]any, len(want))
		ptrs := make([]any, len(want))
		for i := range got {
			ptrs[i] = &got[i]
		}
		if err := row.Scan(ptrs...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("%s = %v, want %v", q, got, want)
				return
			}
		}
	}
	check(`SELECT bytes_out, bytes_in, pkts_out, pkts_in, qname FROM connections WHERE flow_key = 'in'`, int64(50000), int64(1000), int64(40), int64(10), "")
	check(`SELECT bytes_out, bytes_in FROM connections WHERE flow_key = 'out'`, int64(300), int64(4000))
	check(`SELECT bytes_out, bytes_in FROM flows WHERE flow_key = 'in'`, int64(50000), int64(1000))
	check(`SELECT group_concat(rel || ':' || src || '>' || dst, ' ') FROM (SELECT * FROM facts ORDER BY id)`,
		"serves:6>7 fingerprint:1>8")
	check(`SELECT direction, remote_port, bytes_out, bytes_in FROM traffic_hourly WHERE remote_ip = '198.51.100.7'`, "in", int64(443), int64(50000), int64(1000))
	check(`SELECT direction, remote_port, bytes_out FROM traffic_hourly WHERE remote_ip = '93.184.215.14'`, "out", int64(443), int64(300))
	check(`SELECT direction, bytes_out FROM traffic_hourly WHERE remote_ip = '192.0.2.1'`, "out", int64(5))
	if _, err := st.Flows(context.Background(), win(0, time.Hour)); err != nil {
		t.Fatal(err)
	}
}
