package store

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/testutil"
	"github.com/xen0bit/netgraph/internal/wire"
)

// A label set by hand beats every automatic name, survives later
// announcements and a restart, and clearing it restores the newest automatic
// name.
func TestSetDeviceLabel(t *testing.T) {
	ctx := context.Background()
	at := testutil.Base
	path := filepath.Join(t.TempDir(), "ng.db")
	cfg := Config{Now: func() time.Time { return at.Add(time.Hour) }}
	st, err := Open(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	mac := testutil.Phone.MAC.String()
	win := model.Filter{From: at, To: at.Add(time.Hour), Device: mac}
	dhcp := func(seq uint64, ts time.Time, name string) wire.Event {
		return wire.Event{Seq: seq, Type: wire.TypeDHCP, TS: ts, DHCP: &wire.DHCP{
			Version: 4, MsgType: "ACK", MAC: mac, YourIP: testutil.Phone.IP, Hostname: name,
		}}
	}
	label := func() model.Device {
		t.Helper()
		devs, err := st.Devices(ctx, win)
		if err != nil || len(devs) != 1 {
			t.Fatalf("devices: %v %+v", err, devs)
		}
		return devs[0]
	}
	if _, err := st.Ingest(ctx, "router", "b1", []wire.Event{dhcp(1, at, "alice-iphone")}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetDeviceLabel(ctx, strings.ToUpper(mac), "  Alice's phone "); err != nil {
		t.Fatal(err)
	}
	if d := label(); d.Label != "Alice's phone" || !d.UserLabel || d.AutoLabel != "alice-iphone" {
		t.Fatalf("after set: %+v", d)
	}
	// A new automatic name is tracked but does not replace the user's.
	if _, err := st.Ingest(ctx, "router", "b1", []wire.Event{dhcp(2, at.Add(time.Minute), "alice-iphone-15")}); err != nil {
		t.Fatal(err)
	}
	if d := label(); d.Label != "Alice's phone" || d.AutoLabel != "alice-iphone-15" {
		t.Fatalf("after DHCP: %+v", d)
	}
	// It survives a restart (the caches are rebuilt from the database).
	st.Close()
	if st, err = Open(path, cfg); err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if d := label(); d.Label != "Alice's phone" {
		t.Fatalf("after reopen: %+v", d)
	}
	if err := st.SetDeviceLabel(ctx, mac, ""); err != nil {
		t.Fatal(err)
	}
	if d := label(); d.Label != "alice-iphone-15" || d.UserLabel || d.AutoLabel != "" {
		t.Fatalf("after clear: %+v", d)
	}

	if err := st.SetDeviceLabel(ctx, "02:00:00:00:99:99", "x"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown device: %v", err)
	}
	for _, bad := range []string{strings.Repeat("x", MaxLabel+1), "bell\a", "line\nbreak"} {
		if err := st.SetDeviceLabel(ctx, mac, bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("label %q: %v", bad, err)
		}
	}
	if err := st.SetDeviceLabel(ctx, "not-a-mac", "x"); !errors.Is(err, ErrInvalid) {
		t.Errorf("bad MAC: %v", err)
	}
}
