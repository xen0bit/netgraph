package store

import (
	"context"
	"path/filepath"
	"testing"
)

// tableErasure says how each table's data leaves. A new table fails this test
// until someone decides: db forget and db purge must not leave it behind by
// accident. Rows are checked by hand here; TestErasure* check the behaviour.
var tableErasure = map[string]string{
	"sensors":           "operational: a sensor's name and counters, not about any device",
	"sensor_config":     "operational: settings for a sensor, not about any device",
	"archive_location":  "operational: where the archive is. What's in it follows forget and purge",
	"ingest_seq":        "operational: batch sequence numbers",
	"entities":          "forget, purge",
	"facts":             "forget, purge, disk guard",
	"flows":             "forget, purge, disk guard",
	"connections":       "forget, purge, disk guard",
	"dns":               "forget, purge, disk guard",
	"dns_answers":       "forget, purge, disk guard",
	"observations":      "forget, purge, disk guard",
	"traffic_hourly":    "forget, purge, disk guard",
	"dns_hourly":        "forget, purge, disk guard",
	"wifi_handshakes":   "forget, purge",
	"wifi_group_keys":   "forget, purge",
	"anomaly_mutes":     "forget, purge",
	"timeline_events":   "forget, purge, disk guard",
	"annotations":       "forget, purge",
	"bookmarks":         "forget, purge",
	"incidents":         "forget, purge",
	"incident_entities": "forget, purge",
	"incident_notes":    "forget, purge",
	"incident_evidence": "forget, purge",
	"traffic_minute":    "forget, purge, disk guard",
	"map_pins":          "forget, purge; too small for the disk guard to matter",
	"findings":          "forget, purge; too small for the disk guard to matter",
	"audit_log":         "forget, purge; too small for the disk guard to matter",
	"policies":          "forget, purge; configuration, not observations",
	"policy_rules":      "forget, purge; configuration, not observations",
	"rule_groups":       "forget, purge; configuration, not observations",
	"blocklists":        "forget, purge; configuration, not observations",
	"blocklist_entries": "forget, purge; configuration, not observations",
	"profiles":          "forget, purge; configuration, not observations",
	"network_triggers":  "forget, purge; configuration, not observations",
	"policy_decisions":  "forget, purge; decisions are observations of traffic",
	"app_purposes":      "forget, purge; metadata, not observations",
	"agents":            "forget, purge; agent identity, not observations",
	"agent_processes":   "forget, purge; process observations",
	"agent_connections": "forget, purge; connection observations",
}

func TestEveryTableHasAnErasureDecision(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "ng.db"), Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	rows, err := st.r.QueryContext(context.Background(), `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		seen[name] = true
		if tableErasure[name] == "" {
			t.Errorf("table %s has no erasure decision: add it to db forget, db purge and the disk guard as it needs, then to tableErasure", name)
		}
	}
	for name := range tableErasure {
		if !seen[name] {
			t.Errorf("tableErasure names %s, which no longer exists", name)
		}
	}
}
