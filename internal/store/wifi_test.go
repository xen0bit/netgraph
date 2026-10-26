package store

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/testutil"
	"github.com/xen0bit/netgraph/internal/wire"
)

func TestWiFiIngest(t *testing.T) {
	ctx := context.Background()
	at := testutil.Base
	st, err := Open(filepath.Join(t.TempDir(), "ng.db"), Config{Now: func() time.Time { return at.Add(time.Hour) }})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	ap, client := "aa:bb:cc:00:00:01", "3c:22:fb:01:02:03"
	events := []wire.Event{
		{Seq: 1, Type: wire.TypeWiFi, TS: at, WiFi: &wire.WiFi{
			Kind: "beacon", BSSID: ap, SSID: "cafe", Channel: 6, Signal: -40,
			Security: "wpa2", Ciphers: []string{"CCMP"}, AKMs: []string{"PSK"},
		}},
		{Seq: 2, Type: wire.TypeWiFi, TS: at.Add(time.Second), WiFi: &wire.WiFi{
			Kind: "probe_request", Client: client, SSID: "cafe", Security: "wpa2",
		}},
		{Seq: 3, Type: wire.TypeWiFi, TS: at.Add(2 * time.Second), WiFi: &wire.WiFi{
			Kind: "association_request", BSSID: ap, Client: client, SSID: "cafe",
		}},
		{Seq: 4, Type: wire.TypeWiFi, TS: at.Add(3 * time.Second), WiFi: &wire.WiFi{
			Kind: "handshake", BSSID: ap, Client: client,
			EAPOL: &wire.EAPOL{Message: 2, Version: 2, Cipher: "CCMP", Valid: true, Installed: true},
		}},
		{Seq: 5, Type: wire.TypeWiFi, TS: at.Add(4 * time.Second), WiFi: &wire.WiFi{
			Kind: "deauthentication", BSSID: ap, Client: client, Reason: 3,
		}},
		// Hostile input: a MAC that is not a MAC is ignored, not stored.
		{Seq: 6, Type: wire.TypeWiFi, TS: at.Add(5 * time.Second), WiFi: &wire.WiFi{
			Kind: "beacon", BSSID: "not a mac", SSID: "evil",
		}},
	}
	if _, err := st.Ingest(ctx, "mon", "boot", events); err != nil {
		t.Fatal(err)
	}

	devs, err := st.Devices(ctx, model.Filter{From: at, To: at.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	byMAC := map[string]model.Device{}
	for _, d := range devs {
		byMAC[d.MAC] = d
	}
	if d := byMAC[ap]; d.Role != "access_point" || d.Flows != 0 {
		t.Errorf("ap = %+v", d)
	}
	if _, ok := byMAC[client]; !ok {
		t.Errorf("client missing: %+v", byMAC)
	}

	facts, err := st.Facts(ctx, model.Filter{From: at, To: at.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	rels := map[string]model.Fact{}
	for _, f := range facts {
		rels[f.Rel] = f
	}
	if f, ok := rels[model.RelBroadcasts]; !ok || f.Src != "device:"+ap || f.Dst != "ssid:cafe" || f.Attrs["channel"] != "6" {
		t.Errorf("broadcasts = %+v", rels[model.RelBroadcasts])
	}
	if f, ok := rels[model.RelProbes]; !ok || f.Src != "device:"+client || f.Dst != "ssid:cafe" {
		t.Errorf("probes = %+v", rels[model.RelProbes])
	}
	if f, ok := rels[model.RelAssociates]; !ok || f.Dst != "device:"+ap {
		t.Errorf("associates = %+v", rels[model.RelAssociates])
	}
	if f, ok := rels[model.RelHandshake]; !ok || f.Attrs["message"] != "2" || f.Attrs["valid"] != "1" || f.Attrs["installed"] != "1" {
		t.Errorf("handshake = %+v", rels[model.RelHandshake])
	}

	ent, err := st.Entity(ctx, "device:"+ap, model.Filter{From: at, To: at.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if ent.Attrs["ssid"] != "cafe" || ent.Attrs["wifi_security"] != "wpa2" {
		t.Errorf("ap attrs = %+v", ent.Attrs)
	}
	var sawWiFi bool
	for _, ev := range ent.Timeline {
		if ev.Type == "wifi" {
			sawWiFi = true
		}
	}
	if !sawWiFi {
		t.Errorf("timeline lacks wifi: %+v", ent.Timeline)
	}

	nets, err := st.WiFi(ctx, model.Filter{From: at, To: at.Add(time.Hour)})
	if err != nil || len(nets) != 1 {
		t.Fatalf("wifi networks: %v %+v", err, nets)
	}
	if n := nets[0]; n.BSSID != ap || n.SSID != "cafe" || n.Security != "wpa2" || n.Channel != 6 || n.Clients != 1 {
		t.Errorf("wifi network = %+v", n)
	}

	g, err := st.Graph(ctx, model.Filter{From: at, To: at.Add(time.Hour)}, model.GraphOptions{Identity: true, DNS: true, TopN: -1})
	if err != nil {
		t.Fatal(err)
	}
	var ssidNode bool
	for _, n := range g.Nodes {
		if n.ID == "ssid:cafe" && n.Kind == model.KindSSID && n.Label == "cafe" {
			ssidNode = true
		}
	}
	if !ssidNode {
		t.Errorf("graph lacks ssid node: %+v", g.Nodes)
	}
	if !slices.ContainsFunc(facts, func(f model.Fact) bool { return f.Rel == model.RelBroadcasts }) {
		t.Error("facts missing broadcasts")
	}
}

func TestWiFiKeyStoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	at := testutil.Base
	st, err := Open(filepath.Join(t.TempDir(), "ng.db"), Config{Now: func() time.Time { return at.Add(time.Hour) }})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	ap, sta := "aa:bb:cc:00:00:01", "3c:22:fb:01:02:03"
	an1, sn1 := strings.Repeat("11", 32), strings.Repeat("22", 32)
	an2, sn2 := strings.Repeat("33", 32), strings.Repeat("44", 32)
	evs := []wire.Event{
		{Seq: 1, Type: wire.TypeWiFiKey, TS: at, WiFiKey: &wire.WiFiKey{BSSID: ap, STA: sta, SSID: "cafe", ANonce: an1, SNonce: sn1, KeyVersion: 2}},
		// A newer handshake for the same pair replaces the older one.
		{Seq: 2, Type: wire.TypeWiFiKey, TS: at.Add(time.Minute), WiFiKey: &wire.WiFiKey{BSSID: ap, STA: sta, SSID: "cafe", ANonce: an2, SNonce: sn2, KeyVersion: 2}},
		// Hostile input: a bad MAC and a malformed nonce are dropped, not stored.
		{Seq: 3, Type: wire.TypeWiFiKey, TS: at, WiFiKey: &wire.WiFiKey{BSSID: "not a mac", STA: sta, SSID: "x", ANonce: an1, SNonce: sn1, KeyVersion: 2}},
		{Seq: 4, Type: wire.TypeWiFiKey, TS: at, WiFiKey: &wire.WiFiKey{BSSID: "aa:bb:cc:00:00:09", STA: sta, SSID: "x", ANonce: "short", SNonce: sn1, KeyVersion: 2}},
	}
	if _, err := st.Ingest(ctx, "mon", "boot", evs); err != nil {
		t.Fatal(err)
	}
	recs, err := st.WiFiHandshakes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("want 1 handshake after upsert and hostile drops, got %d: %+v", len(recs), recs)
	}
	r := recs[0]
	if r.BSSID != ap || r.STA != sta || r.SSID != "cafe" || r.ANonce != an2 || r.SNonce != sn2 || r.KeyVersion != 2 {
		t.Fatalf("latest-wins round-trip failed: %+v", r)
	}
}

// Group-key records keep the latest per (AP, key ID); an older one does not
// overwrite, and malformed ones are dropped.
func TestWiFiGroupKeys(t *testing.T) {
	ctx := context.Background()
	at := testutil.Base
	st, err := Open(filepath.Join(t.TempDir(), "ng.db"), Config{Now: func() time.Time { return at.Add(time.Hour) }})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	gtk := func(id int, data string) *wire.WiFiGTK {
		return &wire.WiFiGTK{BSSID: "AA:BB:CC:00:00:01", STA: "3c:22:fb:01:02:03", SSID: "cafe", KeyID: id,
			ANonce: strings.Repeat("11", 32), SNonce: strings.Repeat("22", 32), Descriptor: 2, KeyInfo: 0x13ca, KeyLength: 16,
			IV: strings.Repeat("00", 16), KeyData: data}
	}
	bad := func(f func(*wire.WiFiGTK)) *wire.WiFiGTK { g := gtk(2, "abcd"); f(g); return g }
	evs := []wire.Event{
		{Seq: 1, Type: wire.TypeWiFiGTK, TS: at, WiFiGTK: gtk(1, "aaaa")},
		{Seq: 2, Type: wire.TypeWiFiGTK, TS: at.Add(time.Minute), WiFiGTK: gtk(1, "bbbb")},
		{Seq: 3, Type: wire.TypeWiFiGTK, TS: at.Add(-time.Minute), WiFiGTK: gtk(1, "cccc")}, // older: ignored
		{Seq: 4, Type: wire.TypeWiFiGTK, TS: at, WiFiGTK: gtk(2, "dddd")},
		{Seq: 5, Type: wire.TypeWiFiGTK, TS: at, WiFiGTK: bad(func(g *wire.WiFiGTK) { g.KeyID = 4 })},
		{Seq: 6, Type: wire.TypeWiFiGTK, TS: at, WiFiGTK: bad(func(g *wire.WiFiGTK) { g.KeyData = "zz" })},
		{Seq: 7, Type: wire.TypeWiFiGTK, TS: at, WiFiGTK: bad(func(g *wire.WiFiGTK) { g.KeyData = strings.Repeat("00", 513) })},
		{Seq: 8, Type: wire.TypeWiFiGTK, TS: at, WiFiGTK: bad(func(g *wire.WiFiGTK) { g.IV = "00" })},
		{Seq: 9, Type: wire.TypeWiFiGTK, TS: at, WiFiGTK: bad(func(g *wire.WiFiGTK) { g.BSSID = "ff:ff:ff:ff:ff:ff" })},
	}
	if _, err := st.Ingest(ctx, "mon", "boot", evs); err != nil {
		t.Fatal(err)
	}
	recs, err := st.WiFiGroupKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("want 2 records, got %+v", recs)
	}
	byID := map[int]wire.WiFiGTK{}
	for _, r := range recs {
		byID[r.KeyID] = r
	}
	if r := byID[1]; r.KeyData != "bbbb" || r.BSSID != "aa:bb:cc:00:00:01" || !r.TS.Equal(at.Add(time.Minute)) {
		t.Errorf("key 1 = %+v", r)
	}
	if byID[2].KeyData != "dddd" {
		t.Errorf("key 2 = %+v", byID[2])
	}
}
