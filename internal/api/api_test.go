package api

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/xen0bit/netgraph/internal/apiclient"
	"github.com/xen0bit/netgraph/internal/capture"
	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/sensor"
	"github.com/xen0bit/netgraph/internal/store"
	"github.com/xen0bit/netgraph/internal/testutil"
	"github.com/xen0bit/netgraph/internal/wifi"
	"github.com/xen0bit/netgraph/internal/wire"
)

// serve starts a server and ships the home scenario to it through the
// real shipper, as a sensor would.
func serve(t *testing.T, web fstest.MapFS) (*httptest.Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "ng.db"), store.Config{Now: func() time.Time { return testutil.Base.Add(10 * time.Minute) }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cfg := Config{Store: st, IngestToken: "in-tok", ReadToken: "rd-tok"}
	if web != nil {
		cfg.Web = web
	}
	srv := httptest.NewServer(New(cfg))
	t.Cleanup(srv.Close)

	sh := wire.NewShipper(wire.ShipperConfig{URL: srv.URL, Token: "in-tok", Sensor: "router", MaxEvents: 10})
	src, err := capture.OpenFile(testutil.Home(t).WriteFile())
	if err != nil {
		t.Fatal(err)
	}
	r := &sensor.Runner{Processor: sensor.NewProcessor(sensor.Config{}, sh), Out: sh, Hello: wire.Hello{Name: "router", Version: "test"}}
	if err := r.RunFile(context.Background(), src); err != nil {
		t.Fatal(err)
	}
	if err := sh.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st := sh.Stats(); st.Queued != 0 || st.EventsDropped != 0 || st.BatchesSent < 2 {
		t.Fatalf("shipper: %+v", st)
	}
	return srv, st
}

var window = model.Filter{From: testutil.Base, To: testutil.Base.Add(time.Hour)}

func TestEndToEnd(t *testing.T) {
	srv, st := serve(t, nil)
	c := apiclient.NewClient(srv.URL, "rd-tok")
	ctx := context.Background()

	devs, err := c.Devices(ctx, window)
	if err != nil {
		t.Fatal(err)
	}
	labels := map[string]bool{}
	for _, d := range devs {
		labels[d.Label] = true
	}
	for _, want := range []string{"alice-iphone", "BRN001BA9", "desktop-1", "core-switch"} {
		if !labels[want] {
			t.Errorf("devices lack %q: %v", want, labels)
		}
	}
	flows, err := c.Flows(ctx, model.Filter{From: window.From, To: window.To, Domain: "*.example.com"})
	if err != nil || len(flows) != 1 || flows[0].SNI != "www.example.com" {
		t.Fatalf("flows: %v %+v", err, flows)
	}
	g, err := c.Graph(ctx, window, model.DefaultGraphOptions)
	if err != nil || len(g.Nodes) == 0 || len(g.Edges) == 0 {
		t.Fatalf("graph: %v %+v", err, g)
	}
	sum, err := c.Summary(ctx, window)
	if err != nil || sum.Devices < 5 || sum.DNSQueries != 5 || sum.Precision != model.PrecisionExact {
		t.Fatalf("summary: %v %+v", err, sum)
	}
	sensors, err := c.Sensors(ctx)
	if err != nil || len(sensors) != 1 || sensors[0].Name != "router" || sensors[0].Version != "test" {
		t.Fatalf("sensors: %v %+v", err, sensors)
	}
	if wifi, err := c.WiFi(ctx, window); err != nil || len(wifi) != 0 {
		t.Fatalf("wifi without observations: %v %+v", err, wifi)
	}
	if _, err := st.Ingest(ctx, "router", "wifi-boot", []wire.Event{{Seq: 1, Type: wire.TypeWiFi, TS: testutil.Base.Add(10 * time.Minute),
		WiFi: &wire.WiFi{Kind: "beacon", BSSID: "aa:bb:cc:00:00:01", SSID: "api-net", Channel: 6, Security: "wpa2"}}}); err != nil {
		t.Fatal(err)
	}
	if wifi, err := c.WiFi(ctx, window); err != nil || len(wifi) != 1 || wifi[0].SSID != "api-net" || wifi[0].Channel != 6 {
		t.Fatalf("wifi: %v %+v", err, wifi)
	}
	ent, err := c.Entity(ctx, "domain:www.example.com", window)
	if err != nil || len(ent.Flows) != 1 || len(ent.DNS) != 1 {
		t.Fatalf("entity: %v %+v", err, ent)
	}
	if _, err := c.Entity(ctx, "domain:nope.example", window); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing entity: %v", err)
	}
	ts, err := c.Timeseries(ctx, window, 5*time.Minute)
	if err != nil || len(ts.Buckets) != 12 || ts.StepMS != 300_000 {
		t.Fatalf("timeseries: %v %+v", err, ts)
	}
	for _, format := range []string{"d2", "svg", "txt"} {
		body, err := c.GraphFormat(ctx, model.Filter{From: window.From, To: testutil.Base.Add(15 * time.Second)}, model.DefaultGraphOptions, format, "dark")
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		want := map[string]string{"d2": `"domain:www.example.com"`, "svg": "<svg", "txt": "www.example.com"}[format]
		if !strings.Contains(string(body), want) {
			t.Errorf("%s output lacks %q:\n%.400s", format, want, body)
		}
	}
}

func TestAuth(t *testing.T) {
	srv, _ := serve(t, nil)
	ctx := context.Background()
	if _, err := apiclient.NewClient(srv.URL, "").Devices(ctx, window); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("no token: %v", err)
	}
	if _, err := apiclient.NewClient(srv.URL, "in-tok").Devices(ctx, window); err == nil {
		t.Error("ingest token accepted for reads")
	}
	resp, err := http.Post(srv.URL+"/api/v1/ingest", wire.ContentType, strings.NewReader(`{"seq":1,"type":"stats","ts":"2026-10-25T12:00:00Z"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("anonymous ingest: %s", resp.Status)
	}
	// Plain JSON lines are accepted too, for curl.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/ingest", strings.NewReader(`{"seq":1,"type":"stats","ts":"2026-10-25T12:00:00Z","stats":{"packets":5}}`+"\n"))
	req.Header.Set("Authorization", "Bearer in-tok")
	req.Header.Set(wire.HeaderSensor, "curl")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("jsonl ingest: %s", resp.Status)
	}
	// Health needs no token.
	if resp, err := http.Get(srv.URL + "/healthz"); err != nil || resp.StatusCode != 200 {
		t.Errorf("healthz: %v", err)
	}
	// A bad window is a 400.
	if _, err := apiclient.NewClient(srv.URL, "rd-tok").Devices(ctx, model.Filter{From: window.To, To: window.From}); err == nil || !strings.Contains(err.Error(), "400") {
		t.Errorf("reversed window: %v", err)
	}
}

func TestLiveAndWeb(t *testing.T) {
	web := fstest.MapFS{
		"index.html":  {Data: []byte("<html>netgraph ui</html>")},
		"web.wasm.gz": {Data: gzipped("raw wasm")},
	}
	srv, st := serve(t, web)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/live?token=rd-tok", nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	br := bufio.NewReader(resp.Body)
	if line, _ := br.ReadString('\n'); !strings.HasPrefix(line, ": netgraph live") {
		t.Fatalf("live preamble %q", line)
	}
	go func() {
		ev := wire.Event{Seq: 1, Type: wire.TypeDHCP, TS: testutil.Base.Add(time.Minute), DHCP: &wire.DHCP{Version: 4, MsgType: "ACK", MAC: "aa:bb:cc:00:00:09", Hostname: "late-joiner"}}
		_, _ = st.Ingest(context.Background(), "router", "boot-live", []wire.Event{ev})
	}()
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("live: %v", err)
		}
		if strings.HasPrefix(line, "data: ") && strings.Contains(line, "late-joiner") {
			break
		}
	}

	get := func(path, enc string) (*http.Response, string) {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		if enc != "" {
			req.Header.Set("Accept-Encoding", enc)
		}
		tr := &http.Transport{DisableCompression: true}
		resp, err := (&http.Client{Transport: tr}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b := new(strings.Builder)
		_, _ = bufio.NewReader(resp.Body).WriteTo(b)
		return resp, b.String()
	}
	if _, body := get("/", ""); body != "<html>netgraph ui</html>" {
		t.Errorf("index: %q", body)
	}
	if resp, body := get("/web.wasm", "gzip"); body != string(gzipped("raw wasm")) || resp.Header.Get("Content-Encoding") != "gzip" || resp.Header.Get("Content-Type") != "application/wasm" {
		t.Errorf("wasm gz: %q %v", body, resp.Header)
	}
	if _, body := get("/web.wasm", ""); body != "raw wasm" {
		t.Errorf("wasm inflated: %q", body)
	}
	if _, body := get("/devices/somewhere", ""); body != "<html>netgraph ui</html>" {
		t.Errorf("client route: %q", body)
	}
}

func gzipped(s string) []byte {
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	_, _ = zw.Write([]byte(s))
	zw.Close()
	return b.Bytes()
}

// TestWiFiKeys checks that sensors get the server's Wi-Fi keys and stored
// handshakes with the ingest token, and that keys are never served without
// one.
func TestWiFiKeys(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "ng.db"), store.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	sec, err := wifi.ParseKeyFile(strings.NewReader("wpa2 Home correct horse battery\nwep 2 0102030405\n"))
	if err != nil {
		t.Fatal(err)
	}
	hs := wire.WiFiKey{BSSID: "aa:bb:cc:00:00:01", STA: "02:00:00:00:00:01", SSID: "home",
		ANonce: strings.Repeat("11", 32), SNonce: strings.Repeat("22", 32), KeyVersion: 2}
	if _, err := st.Ingest(context.Background(), "mon", "boot", []wire.Event{
		{Seq: 1, Type: wire.TypeWiFiKey, TS: testutil.Base, WiFiKey: &hs},
	}); err != nil {
		t.Fatal(err)
	}
	fetch := func(cfg Config, token string) (*wire.WiFiKeys, error) {
		cfg.Store, cfg.WiFi = st, sec
		srv := httptest.NewServer(New(cfg))
		defer srv.Close()
		sh := wire.NewShipper(wire.ShipperConfig{URL: srv.URL, Token: token, Sensor: "mon"})
		return sh.FetchWiFiKeys(context.Background())
	}

	if _, err := fetch(Config{IngestToken: "in-tok", ReadToken: "rd-tok"}, "rd-tok"); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("read token fetched wifi keys: %v", err)
	}
	got, err := fetch(Config{IngestToken: "in-tok"}, "in-tok")
	if err != nil {
		t.Fatal(err)
	}
	pmk, _ := wifi.PMK("correct horse battery", "Home")
	if len(got.PMKs) != 1 || got.PMKs[0].SSID != "home" || got.PMKs[0].PMK != hex.EncodeToString(pmk) {
		t.Errorf("pmks = %+v", got.PMKs)
	}
	if len(got.WEP) != 1 || got.WEP[0].Index != 2 || got.WEP[0].Key != "0102030405" {
		t.Errorf("wep = %+v", got.WEP)
	}
	if len(got.Handshakes) != 1 || got.Handshakes[0] != hs {
		t.Errorf("handshakes = %+v", got.Handshakes)
	}
	// With no ingest token (-no-auth) the nonces are still shared, but no key.
	got, err = fetch(Config{}, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.PMKs) != 0 || len(got.WEP) != 0 || len(got.Handshakes) != 1 {
		t.Errorf("unauthenticated server served keys: %+v", got)
	}
}
