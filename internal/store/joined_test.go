package store

import (
	"context"
	"database/sql"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/testutil"
	"github.com/xen0bit/netgraph/internal/wire"
)

// A device is reported once, the first time it uses an address, with the
// name its DHCP exchange gave it; the router's own addresses never count, and
// an upgraded database does not report the devices it already knew.
func TestNewDevices(t *testing.T) {
	ctx := context.Background()
	at := testutil.Base
	path := filepath.Join(t.TempDir(), "ng.db")
	var got []NewDevice
	cfg := Config{Now: func() time.Time { return at.Add(time.Hour) }, OnNewDevice: func(d NewDevice) { got = append(got, d) }}
	st, err := Open(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	mac := testutil.Phone.MAC.String()
	hello := wire.Event{Seq: 1, Type: wire.TypeHello, TS: at, Hello: &wire.Hello{Name: "router", Version: "test",
		Interfaces: []wire.Interface{{Name: "br-lan", MAC: "02:00:5e:00:00:01", Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.1.1/24")}}}}}
	dhcp := wire.Event{Seq: 2, Type: wire.TypeDHCP, TS: at.Add(time.Second), DHCP: &wire.DHCP{
		Version: 4, MsgType: "ACK", MAC: mac, YourIP: testutil.Phone.IP, Hostname: "alice-iphone",
	}}
	if _, err := st.Ingest(ctx, "router", "b1", []wire.Event{hello, dhcp}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].MAC != mac || got[0].Label != "alice-iphone" || got[0].IP != testutil.Phone.IP || got[0].Sensor != "router" {
		t.Fatalf("new devices = %+v", got)
	}
	dhcp.Seq = 3
	if _, err := st.Ingest(ctx, "router", "b1", []wire.Event{dhcp}); err != nil || len(got) != 1 {
		t.Fatalf("a known device was reported again: %+v %v", got, err)
	}
	st.Close()

	// Simulate a database from before the joined attribute: strip it and
	// step the schema back so migration 0004 runs on reopen.
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE entities SET attrs = json_remove(attrs, '$.joined') WHERE kind = 'device'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA user_version = 3`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	got = nil
	if st, err = Open(path, cfg); err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.Ingest(ctx, "router", "b2", []wire.Event{dhcp}); err != nil || len(got) != 0 {
		t.Fatalf("upgrade reported a known device: %+v %v", got, err)
	}
}
