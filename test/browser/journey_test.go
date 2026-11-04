//go:build browser

// Package browser drives the web UI in a real headless Chrome against a real
// server holding the generated home network: the journeys a person takes,
// without the Docker lab. Run with `make browser` (it needs web/dist and a
// local Chrome, or $NETGRAPH_CHROME).
package browser

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/chromedp/chromedp/kb"
)

const readToken = "journey-read-token"

var (
	baseURL string
	server  string // a built netgraph
	webDir  string // the web UI it serves
	sensor  string // a built netgraph-sensor
	replay  string // the capture the server was loaded from
	dataEnd int64  // unix ms: the end of the generated scenario, comfortably past it
)

func TestMain(m *testing.M) {
	code, err := run(m)
	if err != nil {
		fmt.Fprintln(os.Stderr, "browser tests:", err)
		os.Exit(1)
	}
	os.Exit(code)
}

// run builds the server, imports a capture dated ten minutes ago, serves it
// and runs the tests against it.
func run(m *testing.M) (int, error) {
	root, err := filepath.Abs("../..")
	if err != nil {
		return 0, err
	}
	if _, err := os.Stat(filepath.Join(root, "web/dist/index.html")); err != nil {
		return 0, fmt.Errorf("web/dist is missing: run make web.build (%w)", err)
	}
	dir, err := os.MkdirTemp("", "netgraph-browser")
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(dir)
	bin := filepath.Join(dir, "netgraph")
	server = bin
	webDir = filepath.Join(root, "web/dist")
	pcap := filepath.Join(dir, "home.pcap")
	db := filepath.Join(dir, "netgraph.db")
	tok := filepath.Join(dir, "read.token")
	if err := os.WriteFile(tok, []byte(readToken), 0o600); err != nil {
		return 0, err
	}
	sensor = filepath.Join(dir, "netgraph-sensor")
	replay = pcap
	for _, args := range [][]string{
		{"go", "build", "-o", bin, "./cmd/netgraph"},
		{"go", "build", "-o", sensor, "./cmd/netgraph-sensor"},
		{"go", "run", "./internal/testutil/genpcap", pcap},
		{bin, "import", "-db", db, pcap},
	} {
		c := exec.Command(args[0], args[1:]...)
		c.Dir = root
		if out, err := c.CombinedOutput(); err != nil {
			return 0, fmt.Errorf("%v: %w\n%s", args, err, out)
		}
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	addr := l.Addr().String()
	l.Close()
	srv := exec.Command(bin, "serve", "-db", db, "-listen", addr, "-no-auth", "-read-token-file", tok, "-web-dir", filepath.Join(root, "web/dist"))
	srv.Stdout, srv.Stderr = os.Stderr, os.Stderr
	if err := srv.Start(); err != nil {
		return 0, err
	}
	defer func() { _ = srv.Process.Kill(); _ = srv.Wait() }()
	baseURL = "http://" + addr
	dataEnd = time.Now().UnixMilli() + 60_000
	for i := 0; ; i++ {
		resp, err := http.Get(baseURL + "/healthz")
		if err == nil {
			resp.Body.Close()
			break
		}
		if i > 100 {
			return 0, fmt.Errorf("server did not start: %w", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	return m.Run(), nil
}

// session is one browser tab, with the token already stored.
type session struct {
	t        *testing.T
	ctx      context.Context
	requests atomic.Pointer[[]string]
	dialogs  atomic.Int64
}

// open starts a browser at the app with the given hash. initJS runs before
// the app's own scripts on every load.
func open(t *testing.T, hash, initJS string) *session {
	t.Helper()
	return openAt(t, baseURL, hash, initJS)
}

// openAt is open against another server than the shared one.
func openAt(t *testing.T, url, hash, initJS string) *session {
	t.Helper()
	opts := append(chromedp.DefaultExecAllocatorOptions[:], chromedp.NoSandbox, chromedp.WindowSize(1500, 950))
	if p := os.Getenv("NETGRAPH_CHROME"); p != "" {
		opts = append(opts, chromedp.ExecPath(p))
	}
	actx, cancelA := chromedp.NewExecAllocator(context.Background(), opts...)
	t.Cleanup(cancelA)
	ctx, cancelC := chromedp.NewContext(actx)
	t.Cleanup(cancelC)
	ctx, cancelT := context.WithTimeout(ctx, 2*time.Minute)
	t.Cleanup(cancelT)
	s := &session{t: t, ctx: ctx}
	empty := []string{}
	s.requests.Store(&empty)
	chromedp.ListenTarget(ctx, func(ev any) {
		switch e := ev.(type) {
		case *network.EventRequestWillBeSent:
			for {
				old := s.requests.Load()
				next := append(append([]string{}, *old...), e.Request.URL)
				if s.requests.CompareAndSwap(old, &next) {
					break
				}
			}
		case *page.EventJavascriptDialogOpening:
			s.dialogs.Add(1)
			go func() { _ = chromedp.Run(ctx, page.HandleJavaScriptDialog(false)) }()
		}
	})
	s.run(network.Enable(), chromedp.Navigate(url+"/healthz"),
		chromedp.Evaluate(fmt.Sprintf(`localStorage.setItem("netgraph.token", %q)`, readToken), nil))
	if initJS != "" {
		s.run(chromedp.ActionFunc(func(ctx context.Context) error {
			_, err := page.AddScriptToEvaluateOnNewDocument(initJS).Do(ctx)
			return err
		}))
	}
	if hash == "" {
		s.run(chromedp.Navigate(url + "/"))
	} else {
		s.run(chromedp.Navigate(url + "/#" + hash))
	}
	return s
}

func (s *session) run(a ...chromedp.Action) {
	s.t.Helper()
	if err := chromedp.Run(s.ctx, a...); err != nil {
		var status string
		_ = chromedp.Run(s.ctx, chromedp.Text(`#status`, &status, chromedp.ByQuery))
		s.t.Fatalf("browser: %v (status: %q)", err, status)
	}
}

// waitFor polls a JavaScript condition until it is true.
func (s *session) waitFor(what, js string) {
	s.t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		var ok bool
		await := func(p *runtime.EvaluateParams) *runtime.EvaluateParams { return p.WithAwaitPromise(true) }
		if err := chromedp.Run(s.ctx, chromedp.Evaluate(js, &ok, await)); err == nil && ok {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	var status string
	_ = chromedp.Run(s.ctx, chromedp.Text(`#status`, &status, chromedp.ByQuery))
	s.t.Fatalf("timed out waiting for %s (status: %q)", what, status)
}

var awaitPromise = func(p *runtime.EvaluateParams) *runtime.EvaluateParams { return p.WithAwaitPromise(true) }

func (s *session) eval(js string, out any) {
	s.t.Helper()
	s.run(chromedp.Evaluate(js, out))
}

func (s *session) settle() {
	s.t.Helper()
	s.waitFor("the UI to settle", `document.querySelector("#status").textContent.startsWith("updated") && !document.querySelector("#diagram").hasAttribute("aria-busy")`)
}

// seen returns the requests so far whose URL contains the fragment.
func (s *session) seen(frag string) []string {
	var out []string
	for _, u := range *s.requests.Load() {
		if strings.Contains(u, frag) {
			out = append(out, u)
		}
	}
	return out
}

// waitForRequest waits for a request, since a change was made. It's how to know a change
// has begun: the status only says "loading" for as long as the answer takes, which a
// poll can miss on a fast machine.
func (s *session) waitForRequest(what, frag string) {
	s.t.Helper()
	for deadline := time.Now().Add(45 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if len(s.seen(frag)) > 0 {
			return
		}
	}
	s.t.Fatalf("timed out waiting for %s: no request for %s", what, frag)
}

func (s *session) clearRequests() {
	empty := []string{}
	s.requests.Store(&empty)
}

func window() string {
	return fmt.Sprintf("from=%d&to=%d", dataEnd-2*3600_000, dataEnd)
}

// firstDevice asks the API for a device the scenario holds.
func firstDevice(t *testing.T) string {
	t.Helper()
	req, _ := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/devices?from=%d&to=%d", baseURL, dataEnd-2*3600_000, dataEnd), nil)
	req.Header.Set("Authorization", "Bearer "+readToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var devs []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &devs); err != nil || len(devs) == 0 {
		t.Fatalf("no devices: %v %s", err, body)
	}
	return devs[0].ID
}

// Leaving the Recorder must not leave its followed entity filtering every
// view with no visible way to clear it.
func TestLeavingRecorderStopsFollowing(t *testing.T) {
	dev := firstDevice(t)
	s := open(t, window()+"&tab=devices&rec=1&rec_at="+fmt.Sprint(dataEnd)+"&follow="+dev, "")
	s.settle()
	s.waitFor("the follow chip", `!document.querySelector("#rec-follow").hidden`)
	s.clearRequests()
	s.run(chromedp.Click(`#recorder`, chromedp.ByQuery))
	s.waitFor("the recorder to close", `document.querySelector("#recorder-bar").hidden`)
	s.settle()
	sums := s.seen("/api/v1/summary")
	if len(sums) == 0 {
		t.Fatal("no summary request after leaving the recorder")
	}
	if last := sums[len(sums)-1]; strings.Contains(last, "device=") {
		t.Errorf("still filtered after leaving the recorder: %s", last)
	}
}

// Stepping through recorded moments keeps the view the person chose.
func TestRecorderKeepsPanAndZoom(t *testing.T) {
	s := open(t, window(), "")
	s.waitFor("the graph", `Number(document.querySelector("#diagram canvas").dataset.nodes) > 0`)
	s.settle()
	s.run(chromedp.Click(`#recorder`, chromedp.ByQuery))
	s.waitFor("the recorder", `!document.querySelector("#recorder-bar").hidden`)
	s.settle()
	s.waitFor("the graph", `Number(document.querySelector("#diagram canvas").dataset.nodes) > 0`)
	// The listener is on the canvas, and the view is published on the next frame:
	// this must really have zoomed, or stepping has nothing to preserve.
	var fitted, before, after string
	s.eval(`document.querySelector("#diagram canvas").dataset.view`, &fitted)
	s.eval(`(() => { const c = document.querySelector("#diagram canvas"); const r = c.getBoundingClientRect();
		for (let i = 0; i < 4; i++) c.dispatchEvent(new WheelEvent("wheel", {deltaY: -120, clientX: r.left + 200, clientY: r.top + 100, bubbles: true, cancelable: true}));
		return 1; })()`, nil)
	s.waitFor("the zoom", fmt.Sprintf(`document.querySelector("#diagram canvas").dataset.view !== %q`, fitted))
	s.eval(`document.querySelector("#diagram canvas").dataset.view`, &before)
	s.clearRequests()
	s.run(chromedp.Click(`#rec-fwd`, chromedp.ByQuery))
	s.waitForRequest("the step", "/api/v1/summary")
	s.settle()
	if len(s.seen("/api/v1/summary")) == 0 {
		t.Fatal("stepping fetched nothing")
	}
	s.eval(`Number(document.querySelector("#diagram canvas").dataset.nodes) > 0 ? document.querySelector("#diagram canvas").dataset.view : ""`, &after)
	if after == "" {
		t.Fatal("the next moment has no graph to compare")
	}
	if before != after {
		t.Errorf("stepping refit the graph:\n before %s\n after  %s", before, after)
	}
}

// Slow responses must not make playback pile up requests.
func TestPlaybackDoesNotOverlap(t *testing.T) {
	slow := `(() => { const f = window.fetch; window.__inflight = 0; window.__peak = 0;
		window.fetch = async (...a) => {
			const sum = String(a[0]).includes("/api/v1/summary");
			if (sum) { window.__inflight++; window.__peak = Math.max(window.__peak, window.__inflight); }
			try { await new Promise((r) => setTimeout(r, 2500)); return await f(...a); }
			finally { if (sum) window.__inflight--; }
		}; })()`
	s := open(t, window()+"&tab=devices&rec=1&rec_at="+fmt.Sprint(dataEnd-3600_000), slow)
	s.waitFor("the recorder", `!document.querySelector("#recorder-bar").hidden`)
	s.run(chromedp.Click(`#rec-play`, chromedp.ByQuery))
	time.Sleep(7 * time.Second)
	var peak int
	s.eval(`window.__peak`, &peak)
	if peak > 2 {
		t.Errorf("%d summary requests in flight at once during playback", peak)
	}
}

// The slider covers data that exists, not a fixed 30 days.
func TestRecorderSliderCoversTheData(t *testing.T) {
	s := open(t, window()+"&tab=devices&rec=1&rec_at="+fmt.Sprint(dataEnd), "")
	s.settle()
	var minV, maxV string
	s.waitFor("the slider", `!document.querySelector("#recorder-bar").hidden`)
	s.eval(`document.querySelector("#rec-head").min`, &minV)
	s.eval(`document.querySelector("#rec-head").max`, &maxV)
	var lo, hi int64
	fmt.Sscan(minV, &lo)
	fmt.Sscan(maxV, &hi)
	if span := hi - lo; span > 24*3600_000 {
		t.Errorf("the slider spans %.1f days for a scenario of minutes", float64(span)/864e5)
	}
}

// A window of several days shows dates, not just times of day.
func TestLongWindowTablesShowDates(t *testing.T) {
	s := open(t, fmt.Sprintf("from=%d&to=%d&tab=flows", dataEnd-3*864e5, dataEnd), "")
	s.settle()
	s.waitFor("rows", `!!document.querySelector("#t-flows tbody tr[data-i]")`)
	var cell string
	s.eval(`document.querySelector("#t-flows tbody tr[data-i] td").textContent`, &cell)
	if !strings.Contains(cell, "-") {
		t.Errorf("first cell of a 3-day window has no date: %q", cell)
	}
}

// The token never goes in a URL, where proxies log it.
func TestLiveKeepsTokenOutOfURLs(t *testing.T) {
	s := open(t, "live=1&span=3600000&tab=devices", "")
	s.settle()
	time.Sleep(500 * time.Millisecond)
	if got := s.seen("token="); len(got) > 0 {
		t.Errorf("token in URL: %v", got)
	}
	if got := s.seen("/api/v1/live"); len(got) == 0 {
		t.Error("live feed was not opened")
	}
}

// The page needs no download beyond its own small files.
func TestNoEngineDownload(t *testing.T) {
	s := open(t, window(), "")
	s.waitFor("the map", `Number(document.querySelector("#diagram canvas").dataset.nodes) > 0`)
	for _, f := range []string{"worker.js", ".wasm", "wasm_exec"} {
		if got := s.seen(f); len(got) > 0 {
			t.Errorf("fetched %v", got)
		}
	}
	var version string
	s.waitFor("the version", `document.querySelector("#version").textContent.length > 0`)
	s.eval(`document.querySelector("#version").textContent`, &version)
	if !strings.HasPrefix(version, "netgraph") {
		t.Errorf("version %q", version)
	}
}

// An empty window offers a way to the data.
func TestEmptyWindowOffersLatestData(t *testing.T) {
	far := dataEnd - 30*864e5
	// However late the range arrives: nothing redraws the table afterwards.
	slow := `(() => { const f = window.fetch;
		window.fetch = async (...a) => {
			if (String(a[0]).includes("/api/v1/range")) await new Promise((r) => setTimeout(r, 1500));
			return f(...a);
		}; })()`
	s := open(t, fmt.Sprintf("from=%d&to=%d&tab=devices", far-3600_000, far), slow)
	s.waitFor("the jump", `!!document.querySelector("#t-devices [data-jump-latest]")`)
	s.run(chromedp.Click(`#t-devices [data-jump-latest]`, chromedp.ByQuery))
	s.waitFor("rows", `!!document.querySelector("#t-devices tbody tr[data-i]")`)
}

// Bookmarks use the app's dialog, not a blocking browser prompt.
func TestBookmarkUsesAppDialog(t *testing.T) {
	s := open(t, window()+"&tab=devices&rec=1&rec_at="+fmt.Sprint(dataEnd), "")
	s.settle()
	s.waitFor("the recorder", `!document.querySelector("#recorder-bar").hidden`)
	s.run(chromedp.Click(`#rec-bookmark`, chromedp.ByQuery))
	time.Sleep(300 * time.Millisecond)
	if n := s.dialogs.Load(); n > 0 {
		t.Fatalf("%d native dialogs", n)
	}
	s.waitFor("the dialog", `document.querySelector("#input-dialog")?.open === true`)
	s.run(chromedp.SendKeys(`#input-dialog-value`, "before the upgrade", chromedp.ByQuery),
		chromedp.Click(`#input-dialog-ok`, chromedp.ByQuery))
	s.waitFor("the dialog to close", `!document.querySelector("#input-dialog").open`)
	s.waitFor("the bookmark to be stored", fmt.Sprintf(`(async () => {
		const r = await fetch("/api/v1/bookmarks?from=%d&to=%d", {headers: {Authorization: "Bearer %s"}});
		return JSON.stringify(await r.json()).includes("before the upgrade");
	})()`, dataEnd-864e5, dataEnd+1000, readToken))
}

// The Ask box does not promise what Ask cannot do.
func TestAskPlaceholderIsHonest(t *testing.T) {
	s := open(t, window()+"&tab=devices", "")
	s.settle()
	var ph string
	s.eval(`document.querySelector("#ask-q").placeholder`, &ph)
	if strings.Contains(ph, "yesterday") {
		t.Errorf("placeholder promises time parsing: %q", ph)
	}
}

// The graph draws when it is ready, however long the anomaly checks take.
func TestGraphDoesNotWaitForAnomalies(t *testing.T) {
	slow := `(() => { const f = window.fetch;
		window.fetch = async (...a) => {
			if (String(a[0]).includes("/api/v1/anomalies")) await new Promise((r) => setTimeout(r, 60000));
			return f(...a);
		}; })()`
	s := open(t, window(), slow)
	s.waitFor("the graph", `Number(document.querySelector("#diagram canvas").dataset.nodes) > 0`)
	s.waitFor("the summary", `document.querySelector("#summary").textContent.includes("devices")`)
}

// Live mode reads the feed with a token in a header. Real ingest arriving from
// a real sensor must still redraw the page.
func TestLiveRefreshesOnIngest(t *testing.T) {
	s := open(t, "live=1&span=3600000&tab=devices", "")
	s.settle()
	time.Sleep(2500 * time.Millisecond) // past anything the page load scheduled
	s.settle()
	s.clearRequests()
	c := exec.Command(sensor, "run", "-pcap", replay, "-server", baseURL, "-name", "journey")
	if out, err := c.CombinedOutput(); err != nil {
		t.Fatalf("sensor: %v\n%s", err, out)
	}
	deadline := time.Now().Add(10 * time.Second)
	for len(s.seen("/api/v1/summary")) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("ingest did not refresh the page")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// The slider shows where the traffic is, and a followed entity can be cleared
// from an empty window.
func TestRecorderDensityIsDrawn(t *testing.T) {
	s := open(t, window()+"&tab=devices&rec=1&rec_at="+fmt.Sprint(dataEnd), "")
	s.settle()
	s.waitFor("density on the slider", `(() => {
		const c = document.querySelector("#rec-density");
		if (!c.width || !c.height) return false;
		return c.getContext("2d").getImageData(0, 0, c.width, c.height).data.some((v) => v !== 0);
	})()`)
}

// A filter that hides everything can be removed from where it left you.
func TestEmptyFilteredWindowOffersClear(t *testing.T) {
	s := open(t, window()+"&tab=devices&q=device:no-such-device", "")
	s.settle()
	s.waitFor("the clear button", `!!document.querySelector("#t-devices [data-clear-filter]")`)
	s.run(chromedp.Click(`#t-devices [data-clear-filter]`, chromedp.ByQuery))
	s.waitFor("rows", `!!document.querySelector("#t-devices tbody tr[data-i]")`)
}

// Screenshots of what these journeys look like, for a person: NETGRAPH_SHOTS.
func TestScreenshots(t *testing.T) {
	dir := os.Getenv("NETGRAPH_SHOTS")
	if dir == "" {
		t.Skip("set NETGRAPH_SHOTS")
	}
	far := dataEnd - 30*864e5
	for name, hash := range map[string]string{
		"recorder": window() + "&rec=1&rec_at=" + fmt.Sprint(dataEnd) + "&rec_lookback=3600000",
		"empty":    fmt.Sprintf("from=%d&to=%d", far-3600_000, far),
		"long":     fmt.Sprintf("from=%d&to=%d&tab=flows", dataEnd-3*864e5, dataEnd),
		"map":      window(),
		"home":     "",
		"settings": "tab=settings",
	} {
		s := open(t, hash, "")
		s.settle()
		time.Sleep(1500 * time.Millisecond)
		var buf []byte
		s.run(chromedp.CaptureScreenshot(&buf))
		if err := os.WriteFile(filepath.Join(dir, name+".png"), buf, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// The workbench: a passport, the Pulse, and the palette open over chips.
	{
		s := open(t, window()+"&tab=devices&q=dir:out%20app:tls", "")
		s.settle()
		s.run(chromedp.KeyEvent("k", chromedp.KeyModifiers(input.ModifierCtrl)))
		s.run(chromedp.SendKeys(`#palette-q`, "alice", chromedp.ByQuery))
		s.waitFor("results", `[...document.querySelectorAll("#palette-list li[data-i]")].some((l) => l.textContent.includes("alice-iphone"))`)
		var buf []byte
		s.run(chromedp.CaptureScreenshot(&buf))
		if err := os.WriteFile(filepath.Join(dir, "palette.png"), buf, 0o644); err != nil {
			t.Fatal(err)
		}
		s.eval(`[...document.querySelectorAll("#palette-list li[data-i]")].find((l) => l.textContent.includes("alice-iphone")).click()`, nil)
		s.waitFor("the passport", `!!document.querySelector("#passport-body .passport")`)
		time.Sleep(300 * time.Millisecond)
		s.run(chromedp.CaptureScreenshot(&buf))
		if err := os.WriteFile(filepath.Join(dir, "passport.png"), buf, 0o644); err != nil {
			t.Fatal(err)
		}
		s.run(chromedp.Evaluate(`document.querySelector('#subtabs [data-tab="devices"]').click()`, nil))
		s.run(chromedp.Evaluate(`document.querySelector('.tabs [data-area="activity"]').click(); 1`, nil))
		s.waitFor("Activity", `!document.querySelector("#view-flows").hidden`)
		s.run(chromedp.Evaluate(`document.querySelector('#subtabs [data-tab="pulse"]').click(); 1`, nil))
		s.waitFor("Pulse", `!document.querySelector("#view-pulse").hidden`)
		time.Sleep(500 * time.Millisecond)
		if out, err := exec.Command(sensor, "run", "-pcap", replay, "-server", baseURL, "-name", "shots").CombinedOutput(); err != nil {
			t.Fatalf("sensor: %v\n%s", err, out)
		}
		s.waitFor("lines", `document.querySelectorAll("#pulse-list li").length > 3`)
		s.run(chromedp.CaptureScreenshot(&buf))
		if err := os.WriteFile(filepath.Join(dir, "pulse.png"), buf, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Home and the map, dark and on a phone.
	for name, c := range map[string]struct {
		hash string
		dark bool
		w, h int64
	}{
		"home-dark":  {"", true, 1500, 950},
		"map-dark":   {window(), true, 1500, 950},
		"home-phone": {"", false, 390, 844},
		"map-phone":  {window(), false, 390, 844},
		"flows-dark": {window() + "&tab=flows", true, 1500, 950},
	} {
		init := ""
		if c.dark {
			init = `localStorage.setItem("netgraph.theme", "dark");`
		}
		s := open(t, c.hash, init)
		s.run(emulation.SetDeviceMetricsOverride(c.w, c.h, 2, c.w < 500))
		s.settle()
		time.Sleep(1500 * time.Millisecond)
		var buf []byte
		s.run(chromedp.CaptureScreenshot(&buf))
		if err := os.WriteFile(filepath.Join(dir, name+".png"), buf, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// Rollups cannot say what raw records can: the page must not claim it.
func TestHourlyWindowClaimsOnlyWhatItKnows(t *testing.T) {
	s := open(t, fmt.Sprintf("from=%d&to=%d&tab=flows", dataEnd-3*864e5, dataEnd), "")
	s.settle()
	s.waitFor("rows", `!!document.querySelector("#t-flows tbody tr[data-i]")`)
	var text string
	s.eval(`document.querySelector("#summary").textContent + document.querySelector("#t-flows tbody").textContent`, &text)
	for _, claim := range []string{"peak", "opened", "carried"} {
		if strings.Contains(text, claim) {
			t.Errorf("hourly precision claims %q: %s", claim, text)
		}
	}
}

const nodesDrawn = `Number(document.querySelector("#diagram canvas").dataset.nodes) > 0`

// point returns where a JavaScript expression says to click on the page.
func (s *session) point(js string) (x, y float64) {
	s.t.Helper()
	var p struct{ X, Y float64 }
	s.eval(js, &p)
	if p.X == 0 && p.Y == 0 {
		s.t.Fatalf("no point from %s", js)
	}
	return p.X, p.Y
}

func nodePoint(pick string) string {
	return `(() => { const m = document.querySelector("#diagram").__map;
		const d = [...m.nodes.values()].find((n) => ` + pick + `);
		if (!d) return {X: 0, Y: 0};
		const p = m.screenOf(d.id); return {X: p.x, Y: p.y}; })()`
}

// edgePoint is a spot on an edge that no node covers.
const edgePoint = `(() => { const m = document.querySelector("#diagram").__map; const r = m.canvas.getBoundingClientRect();
	for (const d of m.edges.values()) {
		if (d.dying || !d.c || d.data.rel !== "connects") continue;
		const q = {x: .25*d.c.ax + .5*d.c.cx + .25*d.c.bx, y: .25*d.c.ay + .5*d.c.cy + .25*d.c.by};
		if (m.nodeAt(q.x, q.y)) continue;
		return {X: r.left + q.x*m.scale + m.x, Y: r.top + q.y*m.scale + m.y};
	}
	return {X: 0, Y: 0}; })()`

func TestClickNodeOpensDetails(t *testing.T) {
	s := open(t, window(), "")
	s.waitFor("the map", nodesDrawn)
	s.settle()
	x, y := s.point(nodePoint(`n.data.kind === "device"`))
	s.run(chromedp.MouseClickXY(x, y))
	s.waitFor("the details", `!document.querySelector("#panel").hidden && document.querySelector("#panel h2")?.textContent.length > 0`)
	var id string
	s.eval(`document.querySelector("#panel-body .mono").textContent`, &id)
	if !strings.HasPrefix(id, "device:") {
		t.Errorf("details of %q", id)
	}
}

// An edge is a thing you can ask about.
func TestClickEdgeListsConnections(t *testing.T) {
	s := open(t, window(), "")
	s.waitFor("the map", nodesDrawn)
	s.settle()
	s.waitFor("edges to be placed", `[...document.querySelector("#diagram").__map.edges.values()].some((d) => d.c)`)
	x, y := s.point(edgePoint)
	s.run(chromedp.MouseClickXY(x, y))
	s.waitFor("its connections", `document.querySelector("#edge-rows li") !== null`)
	var text string
	s.eval(`document.querySelector("#panel-body").textContent`, &text)
	if !strings.Contains(text, "→") || !strings.Contains(text, "What if") {
		t.Errorf("edge panel: %.300s", text)
	}
}

// Dragging pins a node: it stays through a refresh and a reload, for anyone.
func TestDraggedNodeStaysPinned(t *testing.T) {
	s := open(t, window(), "")
	s.waitFor("the map", nodesDrawn)
	s.settle()
	x, y := s.point(nodePoint(`n.data.kind === "device"`))
	var id string
	s.eval(`(() => { const m = document.querySelector("#diagram").__map; return m.nodeAt(...(() => { const r = m.canvas.getBoundingClientRect(); return [(`+fmt.Sprint(x)+` - r.left - m.x)/m.scale, (`+fmt.Sprint(y)+` - r.top - m.y)/m.scale]; })()).id; })()`, &id)
	s.run(chromedp.ActionFunc(func(ctx context.Context) error {
		for _, ev := range []struct {
			typ  input.MouseType
			x, y float64
		}{{input.MouseMoved, x, y}, {input.MousePressed, x, y}, {input.MouseMoved, x + 30, y + 20}, {input.MouseMoved, x + 90, y + 70}, {input.MouseReleased, x + 90, y + 70}} {
			p := input.DispatchMouseEvent(ev.typ, ev.x, ev.y).WithButton(input.Left).WithClickCount(1)
			if err := p.Do(ctx); err != nil {
				return err
			}
		}
		return nil
	}))
	s.waitFor("the pin to be stored", fmt.Sprintf(`(async () => {
		const r = await fetch("/api/v1/map/pins", {headers: {Authorization: "Bearer %s"}});
		return (await r.json()).some((p) => p.id === %q);
	})()`, readToken, id))
	pos := fmt.Sprintf(`(() => { const d = document.querySelector("#diagram").__map.nodes.get(%q); return d ? Math.round(d.tx) + "," + Math.round(d.ty) : ""; })()`, id)
	var before, after string
	s.eval(pos, &before)
	s.run(chromedp.Reload())
	s.waitFor("the map", nodesDrawn)
	s.settle()
	s.eval(pos, &after)
	if before == "" || before != after {
		t.Errorf("pinned at %q, after a reload %q", before, after)
	}
	// Leave no pin for other tests: positions must not depend on order.
	s.eval(fmt.Sprintf(`fetch("/api/v1/map/pins", {method: "DELETE", headers: {Authorization: "Bearer %s", "Content-Type": "application/json"}, body: JSON.stringify({ids: [%q]})}).then(() => 1)`, readToken, id), nil)
}

// Nodes do not move when the window does: the map is a place.
func TestPositionsSurviveAWindowChange(t *testing.T) {
	s := open(t, window(), "")
	s.waitFor("the map", nodesDrawn)
	s.settle()
	s.eval(`window.__ids = new Set([...document.querySelector("#diagram").__map.nodes.values()].filter((d) => d.data.kind === "device").map((d) => d.id)); 1`, nil)
	all := `JSON.stringify([...document.querySelector("#diagram").__map.nodes.values()].filter((d) => window.__ids.has(d.id)).map((d) => [d.id, Math.round(d.tx), Math.round(d.ty)]).sort())`
	var before, after string
	s.eval(all, &before)
	s.clearRequests()
	s.run(chromedp.Click(`#g-identity`, chromedp.ByQuery))
	s.waitForRequest("the change to land", "/api/v1/graph")
	s.settle()
	s.clearRequests()
	s.run(chromedp.Click(`#g-identity`, chromedp.ByQuery))
	s.waitForRequest("the change to land", "/api/v1/graph")
	s.settle()
	s.eval(all, &after)
	if before != after {
		t.Errorf("devices moved:\n%s\n%s", before, after)
	}
}

func TestContextMenuAndNetworkTextIsNotMarkup(t *testing.T) {
	s := open(t, window(), "")
	s.waitFor("the map", nodesDrawn)
	s.settle()
	x, y := s.point(nodePoint(`n.data.kind === "device"`))
	s.run(chromedp.MouseClickXY(x, y, chromedp.ButtonType(input.Right)))
	s.waitFor("the menu", `!!document.querySelector("#map-menu button")`)
	var labels string
	s.eval(`[...document.querySelectorAll("#map-menu button")].map((b) => b.textContent).join("|")`, &labels)
	for _, want := range []string{"Details", "Filter to this device", "Follow in Recorder", "Add a note"} {
		if !strings.Contains(labels, want) {
			t.Errorf("menu %q lacks %q", labels, want)
		}
	}
	s.run(chromedp.KeyEvent("\u001b"))
	s.waitFor("the menu to close", `!document.querySelector("#map-menu")`)
	// The tooltip, list and panel take a hostile label as text.
	s.eval(`(() => { const m = document.querySelector("#diagram").__map;
		m.show({nodes: [{id: "device:x", kind: "device", label: "<img src=x onerror=window.__pwned=1>", sub: "<b>sub</b>", local: true}], edges: []});
		m.showTip(m.graph.nodes[0], 10, 10); return 1; })()`, nil)
	time.Sleep(200 * time.Millisecond)
	var pwned bool
	s.eval(`!!window.__pwned || !!document.querySelector("#diagram img, #diagram b")`, &pwned)
	if pwned {
		t.Error("a label off the network became markup")
	}
}

// Arrow keys walk the map; Enter opens what they reached; the list has it too.
func TestKeyboardReachesNodes(t *testing.T) {
	s := open(t, window(), "")
	s.waitFor("the map", nodesDrawn)
	s.settle()
	s.run(chromedp.Focus(`#diagram canvas`, chromedp.ByQuery), chromedp.KeyEvent(kb.ArrowDown))
	s.waitFor("a focused node", `document.querySelector("#diagram").__map.focus !== ""`)
	s.run(chromedp.KeyEvent("\r"))
	s.waitFor("the details", `!document.querySelector("#panel").hidden`)
	var n int
	s.eval(`document.querySelectorAll(".map-list button").length`, &n)
	var drawn string
	s.eval(`document.querySelector("#diagram canvas").dataset.nodes`, &drawn)
	if fmt.Sprint(n) != drawn {
		t.Errorf("%d list items for %s nodes", n, drawn)
	}
}

// A selection can be hidden, and brought back.
func TestSelectionBarAndHide(t *testing.T) {
	s := open(t, window(), "")
	s.waitFor("the map", nodesDrawn)
	s.settle()
	var before int
	s.eval(`Number(document.querySelector("#diagram canvas").dataset.nodes)`, &before)
	s.eval(`(() => { const m = document.querySelector("#diagram").__map; const d = [...m.nodes.values()].find((n) => !n.data.local && n.data.kind !== "device") || [...m.nodes.values()][0];
		m.selected = new Set([d.id]); m.h.onSelection([d.id]); return 1; })()`, nil)
	s.waitFor("the bar", `!document.querySelector("#map-selection").hidden`)
	s.run(chromedp.Click(`#map-selection-hide`, chromedp.ByQuery))
	s.waitFor("it to be hidden", fmt.Sprintf(`Number(document.querySelector("#diagram canvas").dataset.nodes) < %d`, before))
	s.waitFor("the way back", `!document.querySelector("#g-unhide").hidden`)
	s.run(chromedp.Click(`#g-unhide`, chromedp.ByQuery))
	s.waitFor("it to return", fmt.Sprintf(`Number(document.querySelector("#diagram canvas").dataset.nodes) === %d`, before))
}

// The budget: 500 nodes and 2,000 edges, drawn with particles, measured in
// the page. Headless Chrome draws in software, so this is a floor on real
// hardware, and the budget is a usable frame rate rather than 60 fps.
func TestMapPerformanceBudget(t *testing.T) {
	s := open(t, window()+"&tab=devices", "")
	s.settle()
	var res struct {
		LayoutMS float64
		FrameMS  float64
		Frames   int
	}
	await := func(p *runtime.EvaluateParams) *runtime.EvaluateParams { return p.WithAwaitPromise(true) }
	s.run(chromedp.Evaluate(`(async () => {
		const { LivingMap } = await import("/js/map/map.js");
		const el = document.createElement("div");
		el.style.cssText = "position:fixed;inset:0;z-index:99;background:#fff";
		document.body.append(el);
		const m = new LivingMap(el);
		const nodes = [], edges = [];
		for (let i = 0; i < 30; i++) nodes.push({id: "device:d" + i, kind: "device", label: "device-" + i, sub: "Vendor · 10.0.0." + i, local: true, bytes_in: 1e6, bytes_out: 1e5});
		for (let i = 0; i < 470; i++) nodes.push({id: "domain:h" + i + ".example.com", kind: "domain", label: "h" + i + ".example.com", sub: "1.2.3." + (i % 250)});
		for (let i = 0; i < 2000; i++) edges.push({from: "device:d" + (i % 30), to: nodes[30 + (i * 7) % 470].id, rel: i % 5 ? "connects" : "queried", bytes_out: 1000 * (i + 1), bytes_in: 50000 * (i + 1), count: 1, ports: ["443/tcp"]});
		const seen = new Set();
		const uniq = edges.filter((e) => { const k = e.from + e.to + e.rel; if (seen.has(k)) return false; seen.add(k); return true; });
		const t0 = performance.now();
		m.show({nodes, edges: uniq}, {spanMS: 3600000});
		const layoutMS = performance.now() - t0;
		await new Promise((r) => setTimeout(r, 3000));
		const out = {LayoutMS: layoutMS, FrameMS: Number(m.canvas.dataset.frameMs), Frames: m.frames.length};
		el.remove();
		return out;
	})()`, &res, await))
	t.Logf("500 nodes, 2000 edges: show %.0f ms, %.1f ms a frame over %d frames", res.LayoutMS, res.FrameMS, res.Frames)
	if res.Frames < 10 {
		t.Errorf("only %d frames in 3s", res.Frames)
	}
	if res.FrameMS > 50 {
		t.Errorf("%.1f ms a frame", res.FrameMS)
	}
	if res.LayoutMS > 500 {
		t.Errorf("show took %.0f ms", res.LayoutMS)
	}
}

// Moving through time asks the server for no new graph: the reel holds it.
func TestScrubbingDrawsFromTheReel(t *testing.T) {
	s := open(t, window(), "")
	s.waitFor("the map", nodesDrawn)
	s.settle()
	s.run(chromedp.Click(`#recorder`, chromedp.ByQuery))
	s.waitFor("the reel", `Number(document.querySelector("#diagram canvas").dataset.active) >= 0 && !document.querySelector("#recorder-bar").hidden`)
	s.settle()
	if len(s.seen("/api/v1/reel?")) == 0 {
		t.Fatal("the Recorder fetched no reel")
	}
	var active string
	s.eval(`document.querySelector("#diagram canvas").dataset.active`, &active)
	if active == "0" || active == "" {
		t.Errorf("no active nodes at the moment on screen: %q", active)
	}
	s.clearRequests()
	// Seek to before the scenario: nothing is active, with nothing asked.
	s.eval(`(() => { const h = document.querySelector("#rec-head"); h.value = String(Number(h.min)); h.dispatchEvent(new Event("input")); return document.querySelector("#diagram canvas").dataset.active; })()`, &active)
	if active != "0" {
		t.Errorf("%s nodes active before anything happened", active)
	}
	if got := append(s.seen("/api/v1/graph"), s.seen("/api/v1/reel?")...); len(got) > 0 {
		t.Errorf("scrubbing asked for %v", got)
	}
	s.waitFor("the tables to catch up", `document.querySelector("#status").textContent.startsWith("updated")`)
	time.Sleep(600 * time.Millisecond)
	s.settle()
	if got := append(s.seen("/api/v1/graph"), s.seen("/api/v1/reel?")...); len(got) > 0 {
		t.Errorf("settling asked for %v", got)
	}
}

// Playing draws frames without asking the server anything.
func TestPlayingOnTheMapMakesNoRequests(t *testing.T) {
	s := open(t, window(), "")
	s.waitFor("the map", nodesDrawn)
	s.settle()
	s.run(chromedp.Click(`#recorder`, chromedp.ByQuery))
	s.waitFor("the bar", `!document.querySelector("#recorder-bar").hidden`)
	s.settle()
	s.eval(`(() => { const h = document.querySelector("#rec-head"); h.value = h.min; h.dispatchEvent(new Event("input")); return 1; })()`, nil)
	time.Sleep(600 * time.Millisecond)
	s.settle()
	s.clearRequests()
	var before, after string
	s.eval(`document.querySelector("#rec-time").textContent`, &before)
	s.run(chromedp.Click(`#rec-play`, chromedp.ByQuery))
	time.Sleep(1200 * time.Millisecond)
	s.eval(`document.querySelector("#rec-time").textContent`, &after)
	if before == after {
		t.Errorf("the head did not move from %s", before)
	}
	if got := s.seen("/api/v1/"); len(got) > 0 {
		t.Errorf("playing asked for %v", got)
	}
	s.run(chromedp.Click(`#rec-play`, chromedp.ByQuery))
	s.waitFor("a refresh on stopping", `document.querySelector("#rec-play").textContent === "▶"`)
}

// Two moments compared colour the map, and it can be cleared.
func TestDiffColoursTheMap(t *testing.T) {
	s := open(t, window(), "")
	s.waitFor("the map", nodesDrawn)
	s.settle()
	s.run(chromedp.Click(`#recorder`, chromedp.ByQuery))
	s.waitFor("the bar", `!document.querySelector("#recorder-bar").hidden`)
	s.settle()
	s.eval(`(() => { const h = document.querySelector("#rec-head"); h.value = h.min; h.dispatchEvent(new Event("input")); return 1; })()`, nil)
	time.Sleep(500 * time.Millisecond)
	s.settle()
	s.run(chromedp.Click(`#rec-diff`, chromedp.ByQuery))
	s.waitFor("A", `document.querySelector("#rec-diff").textContent === "Diff B"`)
	s.eval(`(() => { const h = document.querySelector("#rec-head"); h.value = h.max; h.dispatchEvent(new Event("input")); return 1; })()`, nil)
	time.Sleep(500 * time.Millisecond)
	s.settle()
	s.run(chromedp.Click(`#rec-diff`, chromedp.ByQuery))
	s.waitFor("edges marked added", `(() => { const m = document.querySelector("#diagram").__map; return m.diff && [...m.diff.values()].includes("added"); })()`)
	s.waitFor("the legend", `!document.querySelector("#diff-legend").hidden`)
	s.waitFor("the clear button", `!!document.querySelector("#diff-clear")`)
	s.run(chromedp.Click(`#diff-clear`, chromedp.ByQuery))
	s.waitFor("no marks", `!document.querySelector("#diagram").__map.diff`)
}

// A capsule is one file that replays offline, with no server to ask.
func TestCapsuleReplaysOffline(t *testing.T) {
	req, _ := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/capsule?%s", baseURL, window()), nil)
	req.Header.Set("Authorization", "Bearer "+readToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `id="reel-data"`) {
		t.Fatalf("capsule has no reel: %.300s", body)
	}
	s := open(t, window()+"&tab=devices", "")
	s.settle()
	// A page with no origin and no server: a file someone was sent.
	s.run(chromedp.Navigate("about:blank"))
	s.clearRequests()
	s.run(chromedp.ActionFunc(func(ctx context.Context) error {
		tree, err := page.GetFrameTree().Do(ctx)
		if err != nil {
			return err
		}
		return page.SetDocumentContent(tree.Frame.ID, string(body)).Do(ctx)
	}))
	s.waitFor("the replay", `!document.querySelector("#player").hidden && Number(document.querySelector("#player-map canvas").dataset.nodes) > 0`)
	var at0, at1 string
	s.eval(`document.querySelector("#player-map canvas").dataset.active`, &at1)
	s.eval(`(() => { const h = document.querySelector("#player-head"); h.value = h.min; h.dispatchEvent(new Event("input")); return document.querySelector("#player-map canvas").dataset.active; })()`, &at0)
	if at1 == "0" || at0 != "0" {
		t.Errorf("active nodes: %s at the end, %s at the start", at1, at0)
	}
	if got := s.seen("http"); len(got) > 0 {
		t.Errorf("the capsule reached for %v", got)
	}
}
