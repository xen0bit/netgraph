package store

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/testutil"
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
}

func TestPurgeBefore(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
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
