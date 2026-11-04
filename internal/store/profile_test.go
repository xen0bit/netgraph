package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/classify"
	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/testutil"
	"github.com/xen0bit/netgraph/internal/wire"
)

func deviceByLabel(t *testing.T, st *Store, label string) model.Device {
	t.Helper()
	devs, err := st.Devices(context.Background(), win(0, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range devs {
		if d.Label == label {
			return d
		}
	}
	t.Fatalf("no %q in %+v", label, devs)
	return model.Device{}
}

func TestDevicesAreClassifiedFromTheirFacts(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	phone := deviceByLabel(t, st, "alice-iphone")
	if phone.Type != classify.Phone || phone.TypeConfidence != classify.High || phone.TypeWhy != nil {
		t.Errorf("phone: %q %q, why %v", phone.Type, phone.TypeConfidence, phone.TypeWhy)
	}
	if p := deviceByLabel(t, st, "BRN001BA9"); p.Type != classify.Printer || p.TypeConfidence != classify.High {
		t.Errorf("printer: %q %q", p.Type, p.TypeConfidence)
	}
	// One device's answer says why.
	e, err := st.Entity(ctx, phone.ID, win(0, time.Hour))
	if err != nil || e.Device == nil || len(e.Device.TypeWhy) == 0 {
		t.Fatalf("entity: %+v, %v", e, err)
	}
	// The map is told, for its icons.
	if ids, err := st.deviceIDs(ctx, "type:printer"); err != nil || len(ids) != 1 {
		t.Errorf("type:printer: %v, %v", ids, err)
	}
}

func TestAPersonOverrulesTheClassifier(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	phone := deviceByLabel(t, st, "alice-iphone")
	tablet, alice := classify.Tablet, "Alice"
	if err := st.SetDeviceProfile(ctx, phone.MAC, model.DeviceProfile{Type: &tablet, Owner: &alice, Groups: []string{"family", "family", " "}}); err != nil {
		t.Fatal(err)
	}
	got := deviceByLabel(t, st, "alice-iphone")
	if got.Type != classify.Tablet || !got.UserType || got.TypeConfidence != "" || got.Owner != "Alice" || len(got.Groups) != 1 {
		t.Errorf("after the edit: %+v", got)
	}
	for q, want := range map[string]int{"owner:alice": 1, "group:FAMILY": 1, "type:tablet": 1, "owner:bob": 0} {
		if ids, err := st.deviceIDs(ctx, q); err != nil || len(ids) != want {
			t.Errorf("%s: %v, %v", q, ids, err)
		}
	}
	// A filter by owner really narrows a query.
	flows, err := st.Flows(ctx, model.Filter{From: win(0, time.Hour).From, To: win(0, time.Hour).To, Device: "owner:bob"})
	if err != nil || len(flows) != 0 {
		t.Errorf("owner:bob has flows: %d, %v", len(flows), err)
	}
	// Clearing puts the classifier's word back.
	empty := ""
	if err := st.SetDeviceProfile(ctx, phone.MAC, model.DeviceProfile{Type: &empty, Owner: &empty, Groups: []string{}}); err != nil {
		t.Fatal(err)
	}
	got = deviceByLabel(t, st, "alice-iphone")
	if got.Type != classify.Phone || got.UserType || got.Owner != "" || got.Groups != nil {
		t.Errorf("after clearing: %+v", got)
	}
	// Ingest must not lose what a person said: its cache holds the same row.
	if err := st.SetDeviceProfile(ctx, phone.MAC, model.DeviceProfile{Owner: &alice}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Ingest(ctx, "router", "boot9", nil); err != nil {
		t.Fatal(err)
	}
	if got = deviceByLabel(t, st, "alice-iphone"); got.Owner != "Alice" {
		t.Errorf("ingest lost the owner: %+v", got)
	}
	bad := "fridge"
	if err := st.SetDeviceProfile(ctx, phone.MAC, model.DeviceProfile{Type: &bad}); !errors.Is(err, ErrInvalid) {
		t.Errorf("a bad type: %v", err)
	}
	if err := st.SetDeviceProfile(ctx, phone.MAC, model.DeviceProfile{Groups: []string{"two words"}}); !errors.Is(err, ErrInvalid) {
		t.Errorf("a bad group: %v", err)
	}
	if err := st.SetDeviceProfile(ctx, "00:00:00:00:00:99", model.DeviceProfile{Owner: &alice}); !errors.Is(err, ErrNotFound) {
		t.Errorf("an unknown device: %v", err)
	}
}

// linkStore holds one device under a real MAC that stopped, the same name on a
// private MAC afterwards, and another device online at the same time as both.
func linkStore(t *testing.T) (*Store, string, string) {
	t.Helper()
	base := testutil.Base
	now := base.Add(5 * time.Hour)
	st, err := Open(filepath.Join(t.TempDir(), "ng.db"), Config{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	seq := uint64(0)
	dhcp := func(mac, host string, at time.Duration, class string) wire.Event {
		seq++
		return wire.Event{Seq: seq, Type: wire.TypeDHCP, TS: base.Add(at), DHCP: &wire.DHCP{MAC: mac, Hostname: host, MsgType: "REQUEST", ParamList: "1,3,6", VendorClass: class}}
	}
	const old, private, other = "3c:22:fb:01:02:03", "da:a1:19:00:00:01", "da:a1:19:00:00:02"
	if _, err := st.Ingest(context.Background(), "router", "b1", []wire.Event{
		dhcp(old, "bobs-phone", 0, "x"),
		dhcp(old, "bobs-phone", time.Hour, "x"),
		dhcp(private, "bobs-phone", 2*time.Hour, "x"),
		// Together with the private one all along: it's a different device.
		dhcp(other, "bobs-phone", time.Hour+30*time.Minute, "x"),
		dhcp(other, "bobs-phone", 4*time.Hour, "x"),
	}); err != nil {
		t.Fatal(err)
	}
	return st, private, old
}

func TestSuggestsAPrivateAddressIsAKnownDevice(t *testing.T) {
	st, private, old := linkStore(t)
	ctx := context.Background()
	links, err := st.DeviceLinks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var mine *model.DeviceLink
	for i := range links {
		if links[i].Device.MAC == private {
			mine = &links[i]
		}
	}
	if mine == nil || mine.Same.MAC != old || len(mine.Reasons) == 0 || mine.Reasons[0].Signal != "hostname" {
		t.Fatalf("links: %+v", links)
	}
	// Suggesting changes nothing.
	if e, _ := st.Entity(ctx, "device:"+private, win(0, 5*time.Hour)); e.Device != nil && e.Device.SameAs != "" {
		t.Errorf("suggesting linked it: %+v", e.Device)
	}

	// "Same" links them and brings the name across; undo takes it all back.
	alice := "Bob"
	if err := st.SetDeviceProfile(ctx, old, model.DeviceProfile{Owner: &alice}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetDeviceLabel(ctx, old, "Bob's phone"); err != nil {
		t.Fatal(err)
	}
	if err := st.DecideLink(ctx, private, old, LinkSame); err != nil {
		t.Fatal(err)
	}
	e, err := st.Entity(ctx, "device:"+private, win(0, 5*time.Hour))
	if err != nil || e.Label != "Bob's phone" {
		t.Fatalf("after same: %+v, %v", e, err)
	}
	facts, _ := st.deviceFacts(ctx)
	var got *deviceFacts
	for _, f := range facts {
		if f.mac == private {
			got = f
		}
	}
	if got.sameAs != old || got.owner != "Bob" {
		t.Errorf("after same: %+v", got)
	}
	if links, _ := st.DeviceLinks(ctx); len(links) != 0 && links[0].Device.MAC == private {
		t.Errorf("an answered suggestion is back: %+v", links)
	}
	if err := st.DecideLink(ctx, private, "", LinkUndo); err != nil {
		t.Fatal(err)
	}
	e, _ = st.Entity(ctx, "device:"+private, win(0, 5*time.Hour))
	if e.Label == "Bob's phone" {
		t.Errorf("undo kept the name: %q", e.Label)
	}
	facts, _ = st.deviceFacts(ctx)
	for _, f := range facts {
		if f.mac == private && (f.sameAs != "" || f.owner != "") {
			t.Errorf("after undo: %+v", f)
		}
	}
	// "Different" isn't asked again.
	if err := st.DecideLink(ctx, private, old, LinkDifferent); err != nil {
		t.Fatal(err)
	}
	links, _ = st.DeviceLinks(ctx)
	for _, l := range links {
		if l.Device.MAC == private && l.Same.MAC == old {
			t.Errorf("a refused suggestion is back: %+v", l)
		}
	}
}

// A device online alongside the private address can't be it.
func TestNoLinkWhileBothOnline(t *testing.T) {
	st, _, _ := linkStore(t)
	links, err := st.DeviceLinks(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range links {
		if l.Device.MAC == "da:a1:19:00:00:01" && l.Same.MAC == "da:a1:19:00:00:02" {
			t.Errorf("linked two devices online together: %+v", l)
		}
	}
}

func TestPresenceIntervals(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	p, err := st.Presence(ctx, win(0, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if p.Precision != "minute" || len(p.Devices) == 0 {
		t.Fatalf("%+v", p)
	}
	for _, d := range p.Devices {
		if len(d.Intervals) == 0 {
			t.Errorf("%s has none", d.ID)
		}
		for i, iv := range d.Intervals {
			if iv[0] >= iv[1] || iv[0] < p.FromMS || iv[1] > p.ToMS {
				t.Errorf("%s: interval %v outside %d-%d", d.ID, iv, p.FromMS, p.ToMS)
			}
			if i > 0 && iv[0]-d.Intervals[i-1][1] <= p.GapMS {
				t.Errorf("%s: unmerged %v", d.ID, d.Intervals)
			}
		}
	}
	if _, err := st.Presence(ctx, win(time.Hour, 0)); !errors.Is(err, ErrInvalid) {
		t.Errorf("backwards: %v", err)
	}
	// A filter narrows it, and a window older than per-minute data uses hourly.
	f := win(0, time.Hour)
	f.Device = "type:printer"
	if p, err = st.Presence(ctx, f); err != nil || len(p.Devices) > 1 {
		t.Errorf("printers: %+v, %v", p, err)
	}
	st.cfg.MinuteRetention = time.Second
	if p, err = st.Presence(ctx, win(0, time.Hour)); err != nil || p.Precision != "hour" {
		t.Errorf("old window: %+v, %v", p, err)
	}
}

// db forget is a privacy control: a forgotten MAC must not survive in another
// device's link to it.
func TestForgetTakesLinksToTheDevice(t *testing.T) {
	st, private, old := linkStore(t)
	ctx := context.Background()
	if err := st.DecideLink(ctx, private, old, LinkSame); err != nil {
		t.Fatal(err)
	}
	const third = "da:a1:19:00:00:02"
	if err := st.DecideLink(ctx, third, old, LinkDifferent); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ForgetDevice(ctx, old); err != nil {
		t.Fatal(err)
	}
	if n := tableCount(t, st, `SELECT count(*) FROM entities WHERE attrs LIKE ?`, "%"+old+"%"); n != 0 {
		t.Errorf("%d entities still name the forgotten MAC", n)
	}
	facts, err := st.deviceFacts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range facts {
		if f.sameAs != "" {
			t.Errorf("%s is still linked to %s", f.mac, f.sameAs)
		}
	}
	// And ingest, whose cache holds the rows, must not write the link back.
	if _, err := st.Ingest(ctx, "router", "b9", []wire.Event{{Seq: 1, Type: wire.TypeDHCP, TS: testutil.Base.Add(4 * time.Hour), DHCP: &wire.DHCP{MAC: private, Hostname: "again", MsgType: "REQUEST"}}}); err != nil {
		t.Fatal(err)
	}
	if n := tableCount(t, st, `SELECT count(*) FROM entities WHERE attrs LIKE ?`, "%"+old+"%"); n != 0 {
		t.Errorf("ingest brought the forgotten MAC back on %d entities", n)
	}
}
