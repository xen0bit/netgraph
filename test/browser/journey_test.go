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

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

const readToken = "journey-read-token"

var (
	baseURL string
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
	s.run(network.Enable(), chromedp.Navigate(baseURL+"/healthz"),
		chromedp.Evaluate(fmt.Sprintf(`localStorage.setItem("netgraph.token", %q)`, readToken), nil))
	if initJS != "" {
		s.run(chromedp.ActionFunc(func(ctx context.Context) error {
			_, err := page.AddScriptToEvaluateOnNewDocument(initJS).Do(ctx)
			return err
		}))
	}
	s.run(chromedp.Navigate(baseURL + "/#" + hash))
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
	s.waitFor("the graph", `!!document.querySelector("#diagram svg")`)
	s.settle()
	s.run(chromedp.Click(`#recorder`, chromedp.ByQuery))
	s.waitFor("the recorder", `!document.querySelector("#recorder-bar").hidden`)
	s.settle()
	s.waitFor("the graph", `!!document.querySelector("#diagram svg")`)
	zoom := `(() => { const el = document.querySelector("#diagram"); const r = el.getBoundingClientRect();
		for (let i = 0; i < 4; i++) el.dispatchEvent(new WheelEvent("wheel", {deltaY: -120, clientX: r.left + 200, clientY: r.top + 100, bubbles: true}));
		return document.querySelector("#diagram svg").style.transform; })()`
	var before, after string
	s.eval(zoom, &before)
	s.clearRequests()
	s.run(chromedp.Click(`#rec-fwd`, chromedp.ByQuery))
	s.waitForRequest("the step", "/api/v1/summary")
	s.settle()
	if len(s.seen("/api/v1/summary")) == 0 {
		t.Fatal("stepping fetched nothing")
	}
	s.eval(`document.querySelector("#diagram svg")?.style.transform || ""`, &after)
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

// A table-only visit does not pay for the graph engine.
func TestTablesDoNotLoadTheEngine(t *testing.T) {
	s := open(t, window()+"&tab=devices", "")
	s.settle()
	s.waitFor("rows", `!!document.querySelector("#t-devices tbody tr[data-i]")`)
	time.Sleep(500 * time.Millisecond)
	if got := s.seen("worker.js"); len(got) > 0 {
		t.Errorf("the engine started on a table tab: %v", got)
	}
	var version string
	s.eval(`document.querySelector("#version").textContent`, &version)
	if version == "" {
		t.Error("no version in the footer without the engine")
	}
	// Going to the graph then loads it.
	s.run(chromedp.Click(`[data-tab="graph"]`, chromedp.ByQuery))
	s.waitFor("the graph", `!!document.querySelector("#diagram svg")`)
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
	s.waitFor("the graph", `!!document.querySelector("#diagram svg")`)
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
