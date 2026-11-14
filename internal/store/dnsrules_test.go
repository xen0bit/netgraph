package store

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/testutil"
	"github.com/xen0bit/netgraph/internal/wire"
)

func TestDNSRules(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	phone := testutil.Phone.MAC.String()
	for _, bad := range []model.DNSRule{
		{Action: model.DNSBlock, Pattern: "not a name"},
		{Action: model.DNSBlock, Pattern: "*"}, // would stop every lookup
		{Action: "drop", Pattern: "a.example"},
		{Scope: model.DNSScopeDevice, ScopeValue: "phone", Action: model.DNSBlock, Pattern: "a.example"},
		{Scope: model.DNSScopeGroup, Action: model.DNSBlock, Pattern: "a.example"},
		{Scope: "everyone", Action: model.DNSBlock, Pattern: "a.example"},
	} {
		if _, err := st.SaveDNSRule(ctx, &bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("%+v: err %v, want invalid", bad, err)
		}
	}
	// Patterns are read in the forms people write them.
	r, err := st.SaveDNSRule(ctx, &model.DNSRule{Action: model.DNSBlock, Pattern: "||Ads.Example^", Note: "ads"})
	if err != nil || r.Pattern != "ads.example" || r.Scope != model.DNSScopeAll || r.AUID == "" {
		t.Fatalf("saved %+v, %v", r, err)
	}
	// The same pattern for the same scope replaces it, rather than both.
	again, err := st.SaveDNSRule(ctx, &model.DNSRule{Action: model.DNSAllow, Pattern: "*.ads.example"})
	if err != nil || again.ID != r.ID || again.Action != model.DNSAllow {
		t.Fatalf("again = %+v, %v", again, err)
	}
	dev, err := st.SaveDNSRule(ctx, &model.DNSRule{Scope: model.DNSScopeDevice, ScopeValue: "device:" + phone, Action: model.DNSAllow, Pattern: "*"})
	if err != nil || dev.ScopeValue != phone {
		t.Fatalf("device rule %+v, %v", dev, err)
	}
	if _, err := st.SaveDNSRule(ctx, &model.DNSRule{Scope: model.DNSScopeGroup, ScopeValue: "kids", Action: model.DNSBlock, Pattern: "games.example"}); err != nil {
		t.Fatal(err)
	}
	rules, err := st.DNSRules(ctx)
	if err != nil || len(rules) != 3 || rules[0].Scope != model.DNSScopeAll || rules[2].Scope != model.DNSScopeDevice {
		t.Fatalf("rules = %+v, %v", rules, err)
	}
	fp1, _ := st.DNSFingerprint(ctx)
	if err := st.DeleteDNSRule(ctx, r.ID); err != nil {
		t.Fatal(err)
	}
	if fp2, _ := st.DNSFingerprint(ctx); fp1 == fp2 {
		t.Error("the fingerprint missed a deleted rule")
	}
	if err := st.DeleteDNSRule(ctx, r.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleting twice: %v", err)
	}
	// Forgetting the device takes its rules; everyone's stay.
	if _, err := st.ForgetDevice(ctx, phone); err != nil {
		t.Fatal(err)
	}
	if rules, _ := st.DNSRules(ctx); len(rules) != 1 || rules[0].ScopeValue != "kids" {
		t.Errorf("after forget: %+v", rules)
	}
}

func TestDNSClientsAndStats(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	if err := st.SetDeviceProfile(ctx, testutil.Phone.MAC.String(), model.DeviceProfile{Groups: []string{"kids", "family"}}); err != nil {
		t.Fatal(err)
	}
	clients, err := st.DNSClients(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c, ok := clients[testutil.Phone.IP]
	if !ok || c.MAC != testutil.Phone.MAC.String() || len(c.Groups) != 2 {
		t.Fatalf("phone's address maps to %+v (%v)", c, ok)
	}
	// The DNS server's own lookups, one of them refused.
	at := testutil.Base.Add(5 * time.Minute)
	self := netip.MustParseAddr("192.168.1.1")
	evs := []wire.Event{
		{Type: wire.TypeDNS, TS: at, Seq: 1, DNS: &wire.DNS{Client: testutil.Phone.IP, Server: self, Proto: "udp", QName: "ads.example", QType: "A", RCode: "BLOCKED", BlockedBy: "list:ads"}},
		{Type: wire.TypeDNS, TS: at, Seq: 2, DNS: &wire.DNS{Client: testutil.Phone.IP, Server: self, Proto: "udp", QName: "ads.example", QType: "AAAA", RCode: "BLOCKED", BlockedBy: "list:ads"}},
	}
	if _, err := st.Ingest(ctx, DNSServerSensor, "b", evs); err != nil {
		t.Fatal(err)
	}
	// A sensor seeing the same lookups to the server's address is not counted again.
	st.SetDNSSelf([]netip.Addr{self})
	if _, err := st.Ingest(ctx, "router", "boot1", []wire.Event{{Type: wire.TypeDNS, TS: at, Seq: 1 << 40, DNS: &wire.DNS{Client: testutil.Phone.IP, Server: self, Proto: "udp", QName: "ads.example", QType: "A", RCode: "NOERROR"}}}); err != nil {
		t.Fatal(err)
	}
	stats, err := st.DNSStats(ctx, win(0, 10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	// The home network's 5 lookups and the server's 2; not the sensor's copy.
	if stats.Blocked != 2 || stats.Queries != 7 || len(stats.TopBlocked) != 1 || stats.TopBlocked[0].Name != "ads.example" || stats.TopBlocked[0].Count != 2 {
		t.Fatalf("stats = %+v", stats)
	}
	var phone *model.DNSClientStat
	for i, c := range stats.Clients {
		if c.Device == model.EntityID(model.KindDevice, testutil.Phone.MAC.String()) {
			phone = &stats.Clients[i]
		}
	}
	if phone == nil || phone.Blocked != 2 || phone.DeviceName == "" {
		t.Errorf("phone's stats = %+v in %+v", phone, stats.Clients)
	}
	qs, err := st.DNS(ctx, model.Filter{From: at, To: at.Add(time.Second), Domain: "ads.example"})
	if err != nil {
		t.Fatal(err)
	}
	if len(qs) != 2 || qs[0].BlockedBy != "list:ads" {
		t.Errorf("lookups = %+v", qs)
	}
}
