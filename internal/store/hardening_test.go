package store

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/testutil"
	"github.com/xen0bit/netgraph/internal/wire"
)

// A live database can be copied with `netgraph db backup`; query_only on
// the source must not block VACUUM INTO.
func TestBackup(t *testing.T) {
	st, _, _ := homeStore(t)
	src := st.Path()
	dst := filepath.Join(t.TempDir(), "backup.db")
	b, err := OpenBackup(src, Config{Now: st.cfg.Now})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Backup(context.Background(), dst); err != nil {
		b.Close()
		t.Fatal(err)
	}
	b.Close()
	if fi, err := os.Stat(dst); err != nil || fi.Size() == 0 {
		t.Fatalf("backup file: %v %v", fi, err)
	}
	ro, err := OpenReadOnly(dst, Config{Now: st.cfg.Now})
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	devs, err := ro.Devices(context.Background(), win(0, time.Hour))
	if err != nil || len(devs) == 0 {
		t.Fatalf("backup devices: %v %d", err, len(devs))
	}
}

// A newer binary must say what to do with an older database, not emit a
// SQL error from the first query that meets a missing column.
func TestOpenReadOnlyRejectsOldSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	db := openAt(t, path, 7)
	db.Close()
	if _, err := OpenReadOnly(path, Config{}); err == nil || !strings.Contains(err.Error(), "db migrate") {
		t.Fatalf("old schema: %v", err)
	}
}

// The sparkline and the DNS table must agree under every filter that the
// table supports, at both precisions.
func TestTimeseriesDNSFilters(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	base := win(0, time.Hour)
	base.IP = testutil.ExampleIP.String()
	check := func(f model.Filter, hourly bool) {
		t.Helper()
		sum := 0
		if hourly {
			qs, err := st.dnsHourly(ctx, f, ms(f.From), ms(f.To))
			if err != nil {
				t.Fatal(err)
			}
			for _, q := range qs {
				sum += max(q.Count, 1)
			}
		} else {
			qs, err := st.DNS(ctx, f)
			if err != nil {
				t.Fatal(err)
			}
			sum = len(qs)
		}
		ts, err := st.Timeseries(ctx, f, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		got := 0
		for _, b := range ts.Buckets {
			got += b.DNSQueries
		}
		if got != sum {
			t.Errorf("%s %+v: timeseries DNS %d, table %d", ts.Precision, f, got, sum)
		}
	}
	check(base, false)
	byDomain := win(0, time.Hour)
	byDomain.Domain = "www.example.com"
	check(byDomain, false)

	st.cfg.Now = func() time.Time { return testutil.Base.Add(30 * 24 * time.Hour) }
	if _, err := st.Retain(ctx); err != nil {
		t.Fatal(err)
	}
	hourly := win(0, time.Hour)
	hourly.Domain = "www.example.com"
	check(hourly, true)
}

// Device queries narrow by the same filters as the connection table.
func TestDevicesFilters(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	remote := win(0, time.Hour)
	remote.IP = testutil.ExampleIP.String()
	devs, err := st.Devices(ctx, remote)
	if err != nil || len(devs) != 1 || devs[0].MAC != testutil.Phone.MAC.String() {
		t.Fatalf("remote address filter: %v %+v", err, devs)
	}
	byDomain := win(0, time.Hour)
	byDomain.Domain = "plain.example.net"
	devs, err = st.Devices(ctx, byDomain)
	if err != nil || len(devs) != 1 || devs[0].MAC != testutil.TV.MAC.String() {
		t.Fatalf("domain filter: %v %+v", err, devs)
	}
	byPort := win(0, time.Hour)
	byPort.Port = 443
	devs, err = st.Devices(ctx, byPort)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range devs {
		if d.MAC != testutil.Phone.MAC.String() {
			t.Errorf("port filter listed %s", d.Label)
		}
	}
	if len(devs) == 0 {
		t.Error("port filter found no device")
	}
}

// Hourly summaries count names the connection rollup does not carry: a
// lookup that never became a connection is still a name in the window.
func TestSummaryDomainsHourly(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	exact, err := st.Summary(ctx, win(0, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	st.cfg.Now = func() time.Time { return testutil.Base.Add(30 * 24 * time.Hour) }
	if _, err := st.Retain(ctx); err != nil {
		t.Fatal(err)
	}
	hourly, err := st.Summary(ctx, win(0, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if exact.Domains != hourly.Domains {
		t.Errorf("domains exact %d, hourly %d", exact.Domains, hourly.Domains)
	}
}

func TestForgetDevice(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	devs, _ := st.Devices(ctx, win(0, time.Hour))
	preview, err := st.ForgetDeviceWithOptions(ctx, testutil.Phone.MAC.String(), ForgetOptions{DryRun: true})
	if err != nil || preview.Connections == 0 || !preview.DryRun {
		t.Fatalf("forget dry run: %+v %v", preview, err)
	}
	if got, _ := st.Devices(ctx, win(0, time.Hour)); len(got) != len(devs) {
		t.Fatalf("dry run removed devices: %d -> %d", len(devs), len(got))
	}
	r, err := st.ForgetDevice(ctx, testutil.Phone.MAC.String())
	if err != nil || r.Connections == 0 || r.Facts == 0 || r.DNS == 0 {
		t.Fatalf("forget: %+v %v", r, err)
	}
	after, err := st.Devices(ctx, win(0, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(after) >= len(devs) {
		t.Errorf("devices %d -> %d", len(devs), len(after))
	}
	for _, d := range after {
		if d.MAC == testutil.Phone.MAC.String() {
			t.Error("forgotten device is still listed")
		}
	}
	fl, _ := st.Flows(ctx, win(0, time.Hour))
	for _, f := range fl {
		if f.DeviceMAC == testutil.Phone.MAC.String() {
			t.Errorf("forgotten device still has a flow: %+v", f)
			break
		}
	}
	if got, err := st.Search(ctx, testutil.Phone.IP.String(), 20); err != nil || len(got) != 0 {
		t.Errorf("forgotten address still searchable: %+v %v", got, err)
	}
}

func TestPurgeBefore(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	preview, err := st.PurgeBeforeWithOptions(ctx, testutil.Base.Add(48*time.Hour), PurgeOptions{DryRun: true})
	if err != nil || preview.Connections == 0 || !preview.DryRun {
		t.Fatalf("purge dry run: %+v %v", preview, err)
	}
	if got, _ := st.Devices(ctx, win(0, time.Hour)); len(got) == 0 {
		t.Fatal("dry run purged devices")
	}
	r, err := st.PurgeBefore(ctx, testutil.Base.Add(48*time.Hour))
	if err != nil || r.Connections == 0 || r.Flows == 0 || r.DNS == 0 {
		t.Fatalf("purge: %+v %v", r, err)
	}
	devs, err := st.Devices(ctx, win(0, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(devs) != 0 {
		t.Errorf("purged window still has %d devices: %+v", len(devs), devs)
	}
}

// Rollups carry connection counts separately; they have no packet counts.
func TestHourlyFlowConnections(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	st.cfg.Now = func() time.Time { return testutil.Base.Add(30 * 24 * time.Hour) }
	if _, err := st.Retain(ctx); err != nil {
		t.Fatal(err)
	}
	fl, err := st.Flows(ctx, win(0, time.Hour))
	if err != nil || len(fl) == 0 {
		t.Fatalf("hourly flows: %v %d", err, len(fl))
	}
	for _, f := range fl {
		if f.Connections == 0 || f.PktsOut != 0 || f.PktsIn != 0 {
			t.Errorf("hourly flow counters: %+v", f)
		}
	}
}

// The streaming walkers used by CSV export must produce the same rows as
// the slice API.
func TestWalkersMatchQueries(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	flows, err := st.Flows(ctx, win(0, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var walkedFlows []model.Flow
	if err := st.WalkFlows(ctx, win(0, time.Hour), func(f model.Flow) error {
		walkedFlows = append(walkedFlows, f)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(flows, walkedFlows) {
		t.Errorf("flow walker differs:\n%+v\n%+v", flows, walkedFlows)
	}
	dns, err := st.DNS(ctx, win(0, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var walkedDNS []model.DNSQuery
	if err := st.WalkDNS(ctx, win(0, time.Hour), func(q model.DNSQuery) error {
		walkedDNS = append(walkedDNS, q)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(dns, walkedDNS) {
		t.Errorf("DNS walker differs:\n%+v\n%+v", dns, walkedDNS)
	}
	facts, err := st.Facts(ctx, win(0, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var walkedFacts []model.Fact
	if err := st.WalkFacts(ctx, win(0, time.Hour), func(f model.Fact) error {
		walkedFacts = append(walkedFacts, f)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(facts, walkedFacts) {
		t.Errorf("fact walker differs:\n%+v\n%+v", facts, walkedFacts)
	}
}

func TestWiFiOffset(t *testing.T) {
	at := testutil.Base
	st, err := Open(filepath.Join(t.TempDir(), "wifi.db"), Config{Now: func() time.Time { return at.Add(time.Hour) }})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_, err = st.Ingest(context.Background(), "mon", "boot", []wire.Event{
		{Seq: 1, Type: wire.TypeWiFi, TS: at, WiFi: &wire.WiFi{Kind: "beacon", BSSID: "aa:bb:cc:00:00:31", SSID: "one", Channel: 1, Security: "wpa2"}},
		{Seq: 2, Type: wire.TypeWiFi, TS: at.Add(time.Second), WiFi: &wire.WiFi{Kind: "beacon", BSSID: "aa:bb:cc:00:00:32", SSID: "two", Channel: 6, Security: "wpa2"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	all, err := st.WiFi(context.Background(), win(0, time.Hour))
	if err != nil || len(all) != 2 {
		t.Fatalf("wifi: %+v %v", all, err)
	}
	f := win(0, time.Hour)
	f.Limit, f.Offset = 1, 1
	got, err := st.WiFi(context.Background(), f)
	if err != nil || len(got) != 1 || got[0].BSSID != all[1].BSSID {
		t.Fatalf("wifi offset: %+v %v (all %+v)", got, err, all)
	}
}

func TestBackupRefusesOverwriteAndForces(t *testing.T) {
	st, _, _ := homeStore(t)
	dst := filepath.Join(t.TempDir(), "backup.db")
	if err := os.WriteFile(dst, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := st.Backup(context.Background(), dst); err == nil {
		t.Fatal("backup replaced an existing file without -force")
	}
	if b, _ := os.ReadFile(dst); string(b) != "keep" {
		t.Fatalf("existing file changed: %q", b)
	}
	if err := st.Backup(context.Background(), dst, BackupOptions{Force: true}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(dst)
	if err != nil || fi.Size() == 0 {
		t.Fatalf("backup: %v %v", fi, err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("backup mode = %o, want 600", fi.Mode().Perm())
	}
	if tmps, _ := filepath.Glob(filepath.Join(filepath.Dir(dst), ".backup.db.tmp-*")); len(tmps) != 0 {
		t.Errorf("temporary backup files left: %v", tmps)
	}
}

func TestEmergencyTrim(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	if st.Size() == 0 {
		t.Fatal("empty database size")
	}
	r, err := st.EmergencyTrim(ctx, 1, false)
	if err != nil {
		t.Fatal(err)
	}
	// Facts follow rollup retention, so only -trim-rollups removes them.
	if r.Flows == 0 || r.DNS == 0 || r.Facts != 0 || r.Rollups != 0 {
		t.Errorf("emergency trim counts: %+v", r)
	}
	fl, err := st.Flows(ctx, win(0, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(fl) != 0 {
		t.Errorf("emergency trim left %d flows", len(fl))
	}
	if r, err = st.EmergencyTrim(ctx, 1, true); err != nil {
		t.Fatal(err)
	}
	if r.Facts == 0 || r.Rollups == 0 {
		t.Errorf("emergency trim with rollups: %+v", r)
	}
}

// More concurrent walks than read connections, each looking up labels
// while its cursor is open, must not wait on each other forever.
func TestWalkersDoNotExhaustPool(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- st.WalkFlows(ctx, win(0, time.Hour), func(model.Flow) error {
				time.Sleep(time.Millisecond)
				return nil
			})
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}
