//go:build browser

package browser

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/chromedp"
)

const ctrlModifier = input.ModifierCtrl

const homeDrawn = `!!document.querySelector("#home-body .home-status")`

// A bare address is the landing page, with no time controls to explain.
func TestBareAddressLandsOnHome(t *testing.T) {
	s := open(t, "", "")
	s.waitFor("Home", homeDrawn)
	s.waitFor("a device on Home", `!!document.querySelector("#home-body .device-chip[data-open]")`)
	var hidden bool
	s.eval(`["#from", "#spark", "#filter"].every((q) => document.querySelector(q).offsetParent === null)`, &hidden)
	if !hidden {
		t.Error("the time controls show on Home")
	}
	if got := s.seen("/api/v1/graph"); len(got) != 0 {
		t.Errorf("Home asked for a graph: %v", got)
	}
	// Findings arrive after the page does, and fill in.
	s.waitFor("findings", `!document.querySelector("#home-body .since .spinner")`)
	s.run(chromedp.Click(`#home-body .device-chip[data-open]`, chromedp.ByQuery))
	s.waitFor("details", `!document.querySelector("#panel").hidden && !!document.querySelector("#panel h2")`)
}

// Links from before Home existed still open the map.
func TestOldLinksOpenTheMap(t *testing.T) {
	s := open(t, window(), "")
	s.waitFor("the map", nodesDrawn)
	var ok bool
	s.eval(`!document.querySelector("#view-graph").hidden && document.querySelector('.tabs [data-area="map"]').getAttribute("aria-selected") === "true"`, &ok)
	if !ok {
		t.Error("a link with no view did not open the map")
	}
}

// The areas hold the old tabs, and remember which view was open in each.
func TestAreasRememberTheirView(t *testing.T) {
	s := open(t, window(), "")
	s.waitFor("the map", nodesDrawn)
	s.run(chromedp.Click(`.tabs [data-area="activity"]`, chromedp.ByQuery))
	s.waitFor("Connections", `!document.querySelector("#view-flows").hidden && !document.querySelector("#subtabs").hidden`)
	s.run(chromedp.Click(`#subtabs [data-tab="dns"]`, chromedp.ByQuery))
	s.waitFor("DNS", `!document.querySelector("#view-dns").hidden && location.hash.includes("tab=dns")`)
	s.run(chromedp.Click(`.tabs [data-area="wifi"]`, chromedp.ByQuery))
	s.waitFor("Wi-Fi with no sub-views", `!document.querySelector("#view-wifi").hidden && document.querySelector("#subtabs").hidden`)
	s.run(chromedp.Click(`.tabs [data-area="activity"]`, chromedp.ByQuery))
	s.waitFor("DNS again", `!document.querySelector("#view-dns").hidden`)
	s.run(chromedp.Click(`.tabs [data-area="findings"]`, chromedp.ByQuery))
	s.waitFor("What-if under Findings", `!!document.querySelector("#subtabs #whatif-open")`)
	s.run(chromedp.Click(`#subtabs #whatif-open`, chromedp.ByQuery))
	s.waitFor("the What-if dialog", `document.querySelector("#whatif-dialog").open`)
}

// A link to a sub-view opens it inside its area.
func TestDeepLinkToASubView(t *testing.T) {
	s := open(t, window()+"&tab=destinations", "")
	s.waitFor("Destinations", `!document.querySelector("#view-destinations").hidden && document.querySelector('.tabs [data-area="activity"]').getAttribute("aria-selected") === "true" && document.querySelector('#subtabs [data-tab="destinations"]').getAttribute("aria-current") === "page"`)
}

// The Recorder's strips must not squeeze the map: main takes what is left. The
// old layout counted rows, so opening the Recorder stopped main growing.
func TestRecorderLeavesTheMapRoom(t *testing.T) {
	s := open(t, window()+"&rec=1&rec_at="+fmt.Sprint(dataEnd), "")
	s.waitFor("the map", nodesDrawn)
	s.settle()
	var h, page float64
	s.eval(`document.querySelector("#diagram").clientHeight`, &h)
	s.eval(`innerHeight`, &page)
	if h < page*0.35 {
		t.Errorf("the map is %.0fpx of a %.0fpx page with the Recorder open", h, page)
	}
	var scrolls bool
	s.eval(`document.documentElement.scrollHeight > innerHeight + 1`, &scrolls)
	if scrolls {
		t.Error("the page scrolls: something overflowed the column")
	}
}

// The header is one row on a laptop-sized window, or the map pays for it.
func TestHeaderIsOneRow(t *testing.T) {
	s := open(t, window(), "")
	s.waitFor("the map", nodesDrawn)
	var same bool
	s.eval(`Math.abs(document.querySelector(".window").getBoundingClientRect().top - document.querySelector(".right").getBoundingClientRect().top) < 20`, &same)
	if !same {
		t.Error("the header wrapped at 1500px")
	}
}

// On a phone the map gets most of the screen; its options fold away and come back.
func TestPhoneMapGetsTheScreen(t *testing.T) {
	s := open(t, window(), "")
	s.run(emulation.SetDeviceMetricsOverride(390, 844, 2, true))
	s.waitFor("the map", nodesDrawn)
	s.settle()
	var h float64
	s.eval(`document.querySelector("#diagram").clientHeight`, &h)
	if h < 844*0.45 {
		t.Errorf("the map is %.0fpx of an 844px screen", h)
	}
	var hidden bool
	s.eval(`document.querySelector("#g-collapse").offsetParent === null`, &hidden)
	if !hidden {
		t.Error("the options start open on a phone")
	}
	s.run(chromedp.Click(`#g-more`, chromedp.ByQuery))
	s.waitFor("the options", `document.querySelector("#g-collapse").offsetParent !== null`)
}

// A bar on the traffic chart opens the map at that moment.
func TestHomeBarOpensTheMoment(t *testing.T) {
	s := open(t, "", "")
	s.waitFor("the chart", `!!document.querySelector("#home-body .tbar span[style*='height:'][style*='%']:not([style='height:0.0%'])")`)
	var ts int64
	s.eval(`Number([...document.querySelectorAll("#home-body .tbar")].find((b) => b.firstChild.style.height !== "0%" && parseFloat(b.firstChild.style.height) > 0).dataset.jump)`, &ts)
	s.eval(`[...document.querySelectorAll("#home-body .tbar")].find((b) => Number(b.dataset.jump) === `+fmt.Sprint(ts)+`).click()`, nil)
	s.waitFor("the map", `!document.querySelector("#view-graph").hidden && location.hash.includes("to=`+fmt.Sprint(ts+900_000)+`")`)
	var live string
	s.eval(`document.querySelector("#live").getAttribute("aria-pressed")`, &live)
	if live != "false" {
		t.Error("the moment is still following Live")
	}
}

// "Since you were last here": a returning visitor is told how long it has been,
// and marking it seen empties it.
func TestSinceYouWereLastHere(t *testing.T) {
	back := fmt.Sprintf(`if (!sessionStorage.getItem("seeded")) { sessionStorage.setItem("seeded", "1");
		localStorage.setItem("netgraph.visit", JSON.stringify({since: 0, beat: Date.now() - 2*3600*1000})); }`)
	s := open(t, "", back)
	s.waitFor("the section", `(document.querySelector("#h-since")?.textContent || "").startsWith("Since you were last here")`)
	s.waitFor("findings", `!document.querySelector("#home-body .since .spinner")`)
	s.run(chromedp.Click(`[data-home-seen]`, chromedp.ByQuery))
	s.waitFor("nothing new", `document.querySelector("#home-body .stats b")?.textContent === "0" && !document.querySelector("#home-body .new-devices")`)
	// A reload inside the same session keeps the same "since".
	var before, after string
	s.eval(`localStorage.getItem("netgraph.visit")`, &before)
	s.run(chromedp.Reload())
	s.waitFor("Home", homeDrawn)
	s.eval(`JSON.parse(localStorage.getItem("netgraph.visit")).since + ""`, &after)
	if !strings.Contains(before, `"since":`+after) {
		t.Errorf("the reload moved since: %s -> %s", before, after)
	}
}

// A device named by the network is text on Home.
func TestHomeTextIsNotMarkup(t *testing.T) {
	stub := `const real = window.fetch; window.fetch = async (u, o) => { const r = await real(u, o);
		if (!String(u).includes("/api/v1/home")) return r;
		const h = await r.json(); const bad = "<img src=x onerror=window.__pwned=1>";
		for (const l of [h.active, h.top_talkers, h.new_devices]) for (const d of l) { d.label = bad; d.vendor_short = bad; d.id = '"><b>'; }
		for (const x of h.sensors) x.name = bad;
		return new Response(JSON.stringify(h), {headers: {"content-type": "application/json"}}); };`
	s := open(t, "", stub)
	s.waitFor("Home", homeDrawn)
	time.Sleep(200 * time.Millisecond)
	var pwned bool
	s.eval(`!!window.__pwned || !!document.querySelector("#home-body img, #home-body .device-chip b b")`, &pwned)
	if pwned {
		t.Error("a label off the network became markup")
	}
}

// Settings changes the theme, and offers the sensor command for this server.
func TestSettings(t *testing.T) {
	s := open(t, "tab=settings", "")
	s.waitFor("Settings", `!!document.querySelector("#settings-body .card")`)
	var text string
	s.eval(`document.querySelector("#settings-body").textContent`, &text)
	if !strings.Contains(text, "-server "+baseURL) {
		t.Errorf("no command for this server in %q", text)
	}
	s.run(chromedp.Click(`[data-theme-set="dark"]`, chromedp.ByQuery))
	s.waitFor("dark", `document.documentElement.dataset.theme === "dark" && localStorage.getItem("netgraph.theme") === "dark"`)
	s.run(chromedp.Click(`[data-theme-set=""]`, chromedp.ByQuery))
	s.waitFor("the system's", `!document.documentElement.dataset.theme && !localStorage.getItem("netgraph.theme")`)
	s.run(chromedp.Click(`#subtabs [data-tab="sensors"]`, chromedp.ByQuery))
	s.waitFor("Sensors", `!document.querySelector("#view-sensors").hidden`)
}

// The app installs its shell, and no answer from the API ever goes in the cache.
func TestShellInstallsAndCachesNoData(t *testing.T) {
	s := open(t, "", "")
	s.waitFor("Home", homeDrawn)
	s.waitFor("the service worker", `navigator.serviceWorker.ready.then(() => true)`)
	s.waitFor("the shell cached", `caches.keys().then((k) => k.length === 1 && caches.open(k[0])).then((c) => c && c.match("/js/map/map.js")).then((r) => !!r)`)
	s.run(chromedp.Reload())
	s.waitFor("Home", homeDrawn)
	var bad []string
	if err := chromedp.Run(s.ctx, chromedp.Evaluate(`caches.keys().then((k) => caches.open(k[0])).then((c) => c.keys()).then((r) => r.map((x) => x.url).filter((u) => u.includes("/api/") || u.includes("healthz")))`, &bad, awaitPromise)); err != nil {
		t.Fatal(err)
	}
	if len(bad) != 0 {
		t.Errorf("cached data: %v", bad)
	}
	resp, err := http.Get(baseURL + "/manifest.webmanifest")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/manifest+json") {
		t.Errorf("manifest served as %q", ct)
	}
}

// The first run: a server with nothing shows how to connect a sensor to it, and
// notices the first packets by itself.
func TestFirstRunWaitsForPackets(t *testing.T) {
	dir := t.TempDir()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := exec.CommandContext(ctx, server, "serve", "-db", filepath.Join(dir, "ng.db"), "-listen", addr, "-no-auth", "-web-dir", webDir)
	srv.Stderr = os.Stderr
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); _ = srv.Wait() }()
	url := "http://" + addr
	for i := 0; ; i++ {
		resp, err := http.Get(url + "/healthz")
		if err == nil {
			resp.Body.Close()
			break
		}
		if i > 100 {
			t.Fatal(err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	s := openAt(t, url, "", "")
	s.waitFor("the welcome", `!!document.querySelector("#home-body .first-run .waiting")`)
	var text string
	s.eval(`document.querySelector("#home-body").textContent`, &text)
	if !strings.Contains(text, "-server "+url) {
		t.Errorf("no command for this server in %q", text)
	}
	if out, err := exec.Command(sensor, "run", "-pcap", replay, "-server", url, "-name", "first").CombinedOutput(); err != nil {
		t.Fatalf("sensor: %v\n%s", err, out)
	}
	s.waitFor("the first packets to be noticed", homeDrawn)
}

// Nothing marked hidden is on screen. Twice a class's display has overridden it:
// an empty selection bar floating over the map, a diff legend with no diff, an
// overlay swallowing every click.
func TestHiddenMeansHidden(t *testing.T) {
	for _, hash := range []string{"", window(), window() + "&tab=flows", window() + "&rec=1&rec_at=" + fmt.Sprint(dataEnd)} {
		s := open(t, hash, "")
		s.settle()
		var shown []string
		s.eval(`[...document.querySelectorAll("[hidden]")].filter((e) => getComputedStyle(e).display !== "none").map((e) => e.id || e.className)`, &shown)
		if len(shown) != 0 {
			t.Errorf("%q: hidden but displayed: %v", hash, shown)
		}
	}
}
