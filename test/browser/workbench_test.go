//go:build browser

package browser

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/chromedp/chromedp/kb"
)

func (s *session) ctrlK() {
	s.t.Helper()
	s.run(chromedp.KeyEvent("k", chromedp.KeyModifiers(ctrlModifier)))
	s.waitFor("the palette", `document.querySelector("#palette").open`)
}

// Commands, by fuzzy match, from anywhere, even while typing elsewhere.
func TestPaletteRunsCommands(t *testing.T) {
	s := open(t, window(), "")
	s.waitFor("the map", nodesDrawn)
	s.run(chromedp.Focus(`#filter`, chromedp.ByQuery))
	s.ctrlK()
	s.run(chromedp.SendKeys(`#palette-q`, "pulse", chromedp.ByQuery))
	s.waitFor("the command", `document.querySelector('#palette-list [aria-selected="true"]')?.textContent.includes("Pulse")`)
	s.run(chromedp.SendKeys(`#palette-q`, kb.Enter, chromedp.ByQuery))
	s.waitFor("Pulse", `!document.querySelector("#palette").open && !document.querySelector("#view-pulse").hidden`)
	s.ctrlK()
	s.run(chromedp.KeyEvent(kb.Escape))
	s.waitFor("it to close", `!document.querySelector("#palette").open`)
}

// A time typed in the palette moves the window.
func TestPaletteGoesToATime(t *testing.T) {
	s := open(t, window(), "")
	s.waitFor("the map", nodesDrawn)
	s.ctrlK()
	s.run(chromedp.SendKeys(`#palette-q`, "yesterday 3pm", chromedp.ByQuery))
	s.waitFor("the time", `document.querySelector("#palette-list .palette-head")?.textContent === "Go to a time"`)
	s.run(chromedp.SendKeys(`#palette-q`, kb.Enter, chromedp.ByQuery))
	var hour int
	s.waitFor("the window", `!document.querySelector("#palette").open`)
	time.Sleep(100 * time.Millisecond)
	s.eval(`(() => { const p = new URLSearchParams(location.hash.slice(1)); return new Date(Number(p.get("to")) - 1800000).getHours(); })()`, &hour)
	if hour != 15 {
		t.Errorf("the window is centred on hour %d", hour)
	}
	var live string
	s.eval(`document.querySelector("#live").getAttribute("aria-pressed")`, &live)
	if live != "false" {
		t.Error("a moment in the past is following Live")
	}
}

// A device found in the palette opens its passport, and a link holds it.
func TestPaletteFindsADeviceAndItsPassport(t *testing.T) {
	s := open(t, window(), "")
	s.waitFor("the map", nodesDrawn)
	s.ctrlK()
	s.run(chromedp.SendKeys(`#palette-q`, "alice", chromedp.ByQuery))
	s.waitFor("the device", `[...document.querySelectorAll("#palette-list li[data-i]")].some((l) => l.textContent.includes("alice-iphone"))`)
	s.eval(`[...document.querySelectorAll("#palette-list li[data-i]")].find((l) => l.textContent.includes("alice-iphone")).click()`, nil)
	s.waitFor("the passport", `document.querySelector("#passport-body h2")?.textContent === "alice-iphone"`)
	var text string
	s.eval(`document.querySelector("#passport-body").textContent`, &text)
	for _, want := range []string{"This week", "When it's busy", "What it talked to", "www.example.com"} {
		if !strings.Contains(text, want) {
			t.Errorf("the passport lacks %q: %s", want, text)
		}
	}
	var slots int
	s.eval(`document.querySelectorAll("#passport-body .tchart")[1].children.length`, &slots)
	if slots != 14 {
		t.Errorf("the two-week chart has %d slots", slots)
	}
	s.waitFor("the link", `location.hash.includes("tab=passport") && location.hash.includes("device=device")`)
	s.run(chromedp.Reload())
	s.waitFor("the same passport", `document.querySelector("#passport-body h2")?.textContent === "alice-iphone"`)
}

func TestPassportFromDetailsAndBackToTheMap(t *testing.T) {
	dev := firstDevice(t)
	s := open(t, window()+"&tab=devices&open="+dev, "")
	s.waitFor("the link", `!!document.querySelector("#panel a[data-passport]")`)
	s.run(chromedp.Click(`#panel a[data-passport]`, chromedp.ByQuery))
	s.waitFor("the passport", `!!document.querySelector("#passport-body .passport") && document.querySelector("#panel").hidden`)
	s.run(chromedp.Click(`[data-pp-map]`, chromedp.ByQuery))
	s.waitFor("the filtered map", `!document.querySelector("#view-graph").hidden && document.querySelector("#filter").value.startsWith("device:") && !!document.querySelector("#filter-chips .chip")`)
}

// The palette's time reading, directly, against a fixed clock.
func TestParseWhen(t *testing.T) {
	s := open(t, "", "")
	var out []string
	js := `import("/js/palette.js").then(({parseWhen}) => {
		const now = new Date(2026, 9, 28, 16, 30).getTime(); // a Wednesday
		const f = (ms) => { const d = new Date(ms); return d.getMonth()+1 + "/" + d.getDate() + " " + d.getHours() + ":" + d.getMinutes(); };
		return ["yesterday 3pm", "today 09:00", "3pm", "5pm", "2 hours ago", "last 24h", "90m", "monday", "tuesday at 12am", "2026-10-25 14:00", "2026-10-25", "2026-02-30", "hello", "15", "alice-iphone", "25:00", "13pm"].map((q) => {
			const w = parseWhen(q, now);
			return q + "=" + (w ? f(w.to - (w.span === 3600000 ? 1800000 : 0)) + (w.span === 3600000 ? "" : " span " + w.span/3600000 + "h") + (w.live ? " live" : "") : "none");
		});
	})`
	if err := chromedp.Run(s.ctx, chromedp.Evaluate(js, &out, awaitPromise)); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"yesterday 3pm=10/27 15:0", "today 09:00=10/28 9:0", "3pm=10/28 15:0", "5pm=10/27 17:0", "2 hours ago=10/28 14:30",
		"last 24h=10/28 16:30 span 24h live", "90m=10/28 16:30 span 1.5h live", "monday=10/27 0:0 span 24h", "tuesday at 12am=10/27 0:0",
		"2026-10-25 14:00=10/25 14:0", "2026-10-25=10/26 0:0 span 24h", "2026-02-30=none", "hello=none", "15=none", "alice-iphone=none", "25:00=none", "13pm=none",
	}
	if got, exp := strings.Join(out, "\n"), strings.Join(want, "\n"); got != exp {
		t.Errorf("got:\n%s\nwant:\n%s", got, exp)
	}
}

// Chips are the text filter: suggestions fill it, the × empties it, and hostile
// text stays text.
func TestFilterChips(t *testing.T) {
	s := open(t, window()+"&tab=devices", "")
	s.settle()
	s.run(chromedp.SendKeys(`#filter`, "di", chromedp.ByQuery))
	s.waitFor("the key", `document.querySelector("#filter-suggest li")?.textContent.startsWith("dir:")`)
	s.run(chromedp.SendKeys(`#filter`, kb.ArrowDown+kb.Enter, chromedp.ByQuery))
	s.waitFor("its values", `document.querySelector("#filter").value === "dir:" && [...document.querySelectorAll("#filter-suggest li")].some((l) => l.textContent.startsWith("dir:out"))`)
	s.run(chromedp.SendKeys(`#filter`, kb.ArrowDown+kb.Enter, chromedp.ByQuery))
	s.waitFor("the chip", `document.querySelector("#filter-chips .chip span")?.textContent === "dir:out" && location.hash.includes("q=dir%3Aout")`)
	s.settle()
	s.run(chromedp.Click(`#filter-chips .chip button`, chromedp.ByQuery))
	s.waitFor("no chip", `document.querySelector("#filter-chips").hidden && document.querySelector("#filter").value === "" && !location.hash.includes("q=")`)
	h := open(t, window()+"&tab=devices&q=%3Cimg%20src%3Dx%20onerror%3Dwindow.__pwned%3D1%3E", "")
	h.waitFor("the chip", `!!document.querySelector("#filter-chips .chip")`)
	var pwned bool
	h.eval(`!!window.__pwned || !!document.querySelector("#filter-chips img")`, &pwned)
	if pwned {
		t.Error("filter text became markup")
	}
}

// A device search fills a MAC in and shows the name.
func TestFilterSuggestsDevices(t *testing.T) {
	s := open(t, window()+"&tab=devices", "")
	s.settle()
	s.run(chromedp.SendKeys(`#filter`, "device:alice", chromedp.ByQuery))
	s.waitFor("the device", `document.querySelector("#filter-suggest li b")?.textContent === "alice-iphone"`)
	s.run(chromedp.SendKeys(`#filter`, kb.ArrowDown+kb.Enter, chromedp.ByQuery))
	s.waitFor("a chip with its name", `document.querySelector("#filter-chips .chip span")?.textContent === "alice-iphone" && /^device:[0-9a-f:]+/.test(document.querySelector("#filter").value)`)
	s.waitFor("one row", `document.querySelectorAll("#t-devices tbody tr[data-i]").length === 1`)
}

func TestSavedViews(t *testing.T) {
	s := open(t, window()+"&tab=flows&q=app:tls", "")
	s.settle()
	s.run(chromedp.Click(`#view-save`, chromedp.ByQuery))
	s.waitFor("the dialog", `document.querySelector("#input-dialog").open`)
	s.run(chromedp.SendKeys(`#input-dialog-value`, "<b>TLS</b>"+kb.Enter, chromedp.ByQuery))
	s.waitFor("it saved", `document.querySelector("#view-select").options.length === 2`)
	s.run(chromedp.Evaluate(`document.querySelector('.tabs [data-area="devices"]').click()`, nil))
	s.waitFor("Devices", `!document.querySelector("#view-devices").hidden`)
	s.eval(`(() => { const v = document.querySelector("#view-select"); v.value = "0"; v.dispatchEvent(new Event("change")); })()`, nil)
	s.waitFor("the view", `!document.querySelector("#view-flows").hidden && document.querySelector("#filter").value === "app:tls" && document.querySelector("#live").getAttribute("aria-pressed") === "true"`)
	s.run(chromedp.Evaluate(`document.querySelector('.tabs [data-area="settings"]').click()`, nil))
	s.waitFor("it listed", `document.querySelector("#settings-body .saved-list b")?.textContent === "<b>TLS</b>"`)
	s.run(chromedp.Click(`[data-view-delete]`, chromedp.ByQuery))
	s.waitFor("it gone", `document.querySelector("#view-select").options.length === 1`)
}

// The Pulse streams what arrives, pauses, and needs no Live.
func TestPulseStreams(t *testing.T) {
	s := open(t, window()+"&tab=pulse", "")
	s.waitFor("the feed open", `!document.querySelector("#view-pulse").hidden`)
	time.Sleep(500 * time.Millisecond) // the stream connecting
	if out, err := exec.Command(sensor, "run", "-pcap", replay, "-server", baseURL, "-name", "pulse").CombinedOutput(); err != nil {
		t.Fatalf("sensor: %v\n%s", err, out)
	}
	s.waitFor("lines", `document.querySelectorAll("#pulse-list li").length > 0 && document.querySelector("#pulse-empty").hidden`)
	s.waitFor("a named device", `!!document.querySelector("#pulse-list .pulse-who")`)
	s.run(chromedp.Click(`#pulse-list .pulse-who`, chromedp.ByQuery))
	s.waitFor("its details", `!document.querySelector("#panel").hidden`)
	if got := s.seen("token="); len(got) != 0 {
		t.Errorf("a token in a URL: %v", got)
	}
}

// Pause holds lines back, and network text is only ever text.
func TestPulseLines(t *testing.T) {
	s := open(t, "tab=pulse", "")
	var res string
	js := `import("/js/pulse.js").then(({Pulse}) => {
		const ol = document.createElement("ol"); document.body.append(ol);
		const counts = [];
		const p = new Pulse(ol, {onOpen() {}, onCount: (x) => counts.push(x.lines + "/" + x.held.length)});
		const bad = "<img src=x onerror=window.__pwned=1>";
		p.add([{type: "flow", ts: 1000, entity: "device:x", label: bad, detail: bad}]);
		const markup = !!ol.querySelector("img");
		p.setPaused(true);
		p.add([{type: "dhcp", ts: 2000, detail: "held"}]);
		const during = ol.children.length;
		p.setPaused(false);
		const after = ol.children.length, top = ol.firstElementChild.textContent.includes("held");
		const many = Array.from({length: 2000}, (_, i) => ({type: "flow", ts: i, detail: "x" + i}));
		p.add(many);
		return JSON.stringify({markup, during, after, top, capped: ol.children.length, dropped: p.dropped, newest: ol.firstElementChild.textContent.includes("x1999")});
	})`
	if err := chromedp.Run(s.ctx, chromedp.Evaluate(js, &res, awaitPromise)); err != nil {
		t.Fatal(err)
	}
	if res != `{"markup":false,"during":1,"after":2,"top":true,"capped":500,"dropped":1500,"newest":true}` {
		t.Errorf("got %s", res)
	}
}

// bigFlows answers /flows with n rows, as many as a busy window has.
func bigFlows(n int) string {
	return fmt.Sprintf(`const real = window.fetch; window.__sorts = []; window.fetch = async (u, o) => {
		const url = String(u);
		if (!url.includes("/api/v1/flows")) return real(u, o);
		const q = new URL(url, location.href).searchParams;
		window.__sorts.push(q.get("sort") || "");
		const off = Number(q.get("offset") || 0), lim = Number(q.get("limit") || 1000);
		const rows = [];
		for (let i = off; i < Math.min(off + lim, %d); i++) rows.push({key: "k" + i, proto: "tcp", client_ip: "10.0.0.1", client_port: 1000, server_ip: "93.184.216.34", server_port: 443,
			device: "device:aa", device_name: "row-" + i, device_mac: "aa", remote_ip: "93.184.216.34", remote_port: 443, direction: "out", app: "tls", name: i %% 7 ? "" : "a-long-name-" + i + ".example.com",
			first_seen: 1000 + i, last_seen: 2000 + i, state: "opened", bytes_out: i, bytes_in: i});
		return new Response(JSON.stringify(rows), {headers: {"content-type": "application/json"}}); };`, n)
}

// A long table draws what's near the screen, and every row is still reachable.
func TestLongTableDrawsOnlyWhatIsNear(t *testing.T) {
	s := open(t, window()+"&tab=flows", bigFlows(1000))
	s.waitFor("rows", `document.querySelectorAll("#t-flows tbody tr[data-i]").length > 0`)
	s.settle()
	var drawn int
	s.eval(`document.querySelectorAll("#t-flows tbody tr[data-i]").length`, &drawn)
	if drawn == 0 || drawn >= 800 {
		t.Errorf("%d rows drawn of 1000", drawn)
	}
	// The last row, by scrolling there.
	s.eval(`(() => { const v = document.querySelector("#view-flows"); v.scrollTop = v.scrollHeight; return 1; })()`, nil)
	s.waitFor("the last row", `[...document.querySelectorAll("#t-flows tbody tr[data-i]")].some((r) => r.dataset.i === "999")`)
	// Further scrolling swaps a chunk for a blank of the same height.
	s.waitFor("the top to go blank", `!!document.querySelector('#t-flows tbody[data-chunk="0"] tr.chunk-blank')`)
	var kept bool
	s.eval(`(() => { const v = document.querySelector("#view-flows"); return v.scrollTop > 0; })()`, &kept)
	if !kept {
		t.Error("scrolling was lost")
	}
	s.eval(`[...document.querySelectorAll("#t-flows tbody tr[data-i]")].find((r) => r.dataset.i === "999").click()`, nil)
	s.waitFor("the row to open", `!document.querySelector("#panel").hidden`)
}

// Sorting a capped table asks the server, since it holds only the first rows.
func TestCappedTableSortsOnTheServer(t *testing.T) {
	s := open(t, window()+"&tab=flows", bigFlows(5000))
	s.waitFor("rows", `document.querySelectorAll("#t-flows tbody tr[data-i]").length > 0`)
	s.settle()
	s.eval(`[...document.querySelectorAll("#t-flows thead button.sort")].find((b) => b.textContent.startsWith("Sent")).click()`, nil)
	s.waitFor("the server sort", `window.__sorts.at(-1) === "-bytes_out"`)
	s.waitFor("the count", `document.querySelector("#tt-flows .count").textContent.includes("the first 1000") && !document.querySelector("#tt-flows .count").textContent.includes("sorting covers")`)
	s.eval(`document.querySelector("#tt-flows [data-more]").click()`, nil)
	s.waitFor("paging in that order", `window.__sorts.length >= 3 && window.__sorts.at(-1) === "-bytes_out"`)
}

// Columns can be turned off, and stay off.
func TestColumnChoiceSticks(t *testing.T) {
	s := open(t, window()+"&tab=flows", "")
	s.waitFor("rows", `document.querySelectorAll("#t-flows tbody tr[data-i]").length > 0`)
	count := `document.querySelectorAll("#t-flows thead th").length`
	var before, after int
	s.eval(count, &before)
	s.eval(`(() => { const b = [...document.querySelectorAll("#tt-flows .columns input")].find((i) => i.parentElement.textContent.trim() === "App"); b.click(); return 1; })()`, nil)
	s.waitFor("one fewer", fmt.Sprintf(`%s === %d`, count, before-1))
	s.run(chromedp.Reload())
	s.waitFor("rows", `document.querySelectorAll("#t-flows tbody tr[data-i]").length > 0`)
	s.eval(count, &after)
	if after != before-1 {
		t.Errorf("%d columns after a reload, %d before", after, before-1)
	}
	var cells bool
	s.eval(`document.querySelector("#t-flows tbody tr").children.length === document.querySelectorAll("#t-flows thead th").length`, &cells)
	if !cells {
		t.Error("rows and headers disagree")
	}
}
