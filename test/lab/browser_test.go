//go:build lab

package lab

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

// checkWebUI drives the web UI in a headless Chrome (remote, at devtools)
// against the server at ui: it waits for the WASM engine to draw the graph,
// opens a node's details, visits each table, and saves screenshots to
// shotDir for a person to look at.
func checkWebUI(t *testing.T, devtools, ui, token, shotDir string, expect []string) {
	t.Helper()
	actx, cancel := chromedp.NewRemoteAllocator(context.Background(), devtools)
	defer cancel()
	ctx, cancel := chromedp.NewContext(actx)
	defer cancel()
	ctx, cancel = context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()

	var consoleErrors, console []string
	chromedp.ListenTarget(ctx, func(ev any) {
		switch e := ev.(type) {
		case *runtime.EventExceptionThrown:
			consoleErrors = append(consoleErrors, e.ExceptionDetails.Error())
		case *runtime.EventConsoleAPICalled:
			var parts []string
			for _, a := range e.Args {
				parts = append(parts, string(a.Value)+a.Description)
			}
			console = append(console, string(e.Type)+": "+strings.Join(parts, " "))
		}
	})

	shot := func(name string) chromedp.Action {
		return chromedp.ActionFunc(func(ctx context.Context) error {
			if shotDir == "" {
				return nil
			}
			var buf []byte
			if err := chromedp.FullScreenshot(&buf, 90).Do(ctx); err != nil {
				return err
			}
			return os.WriteFile(fmt.Sprintf("%s/%s.jpg", shotDir, name), buf, 0o644)
		})
	}

	var note, svgText string
	// Store the token before the app's first API call: open a page of the
	// origin that is not the app, set it, then load the app.
	err := chromedp.Run(ctx,
		chromedp.EmulateViewport(1600, 1000),
		chromedp.Navigate(ui+"/healthz"),
		chromedp.Evaluate(fmt.Sprintf(`localStorage.setItem("netgraph.token", %q)`, token), nil),
	)
	if err != nil {
		t.Fatalf("browser: %v", err)
	}
	// A wide window ending now covers whatever the lab generated.
	now := time.Now().UnixMilli()
	gctx, gcancel := context.WithTimeout(ctx, 90*time.Second)
	defer gcancel()
	err = chromedp.Run(gctx,
		chromedp.Navigate(fmt.Sprintf("%s/#from=%d&to=%d", ui, now-2*3600*1000, now+60*1000)),
		chromedp.WaitVisible(`#diagram svg`, chromedp.ByQuery),
		chromedp.Text(`#graph-note`, &note, chromedp.ByQuery),
		chromedp.Evaluate(`document.querySelector("#diagram svg").textContent`, &svgText),
		shot("graph"),
		chromedp.Evaluate(`(() => { const el = document.querySelector("#diagram"); const r = el.getBoundingClientRect();
			for (let i = 0; i < 6; i++) el.dispatchEvent(new WheelEvent("wheel", {deltaY: -120, clientX: r.left + r.width / 2, clientY: r.top + r.height / 2, bubbles: true})); })()`, nil),
		shot("graph-zoom"),
		chromedp.Click(`#g-fit`, chromedp.ByQuery),
	)
	if err != nil {
		var status, diag string
		_ = chromedp.Run(ctx, chromedp.Text(`#status`, &status, chromedp.ByQuery), chromedp.Text(`#diagram`, &diag, chromedp.ByQuery), shot("failed"))
		t.Fatalf("graph did not render: %v\nstatus: %q\ndiagram: %q\nexceptions: %v\nconsole: %v", err, status, diag, consoleErrors, console)
	}
	if !strings.Contains(note, "WASM") {
		t.Errorf("graph was not drawn by WASM: %q", note)
	}
	for _, want := range expect {
		if !strings.Contains(svgText, want) {
			t.Errorf("graph lacks %q", want)
		}
	}
	checkKeepsView(t, gctx)

	// Click the first device node and check the detail panel.
	var panel string
	err = chromedp.Run(ctx,
		chromedp.Evaluate(`(() => {
			for (const g of document.querySelectorAll("#diagram svg g[class]")) {
				const c = g.classList[0];
				try { if (atob(c).includes("device:")) { g.querySelector(".shape, rect, path")?.dispatchEvent(new PointerEvent("pointerdown", {bubbles: true, button: 0}));
					g.querySelector(".shape, rect, path")?.dispatchEvent(new PointerEvent("pointerup", {bubbles: true, button: 0})); return true; } } catch {}
			}
			return false })()`, nil),
		chromedp.WaitVisible(`#panel h2`, chromedp.ByQuery),
		chromedp.Sleep(500*time.Millisecond),
		chromedp.Text(`#panel`, &panel, chromedp.ByQuery),
		shot("detail"),
	)
	if err != nil {
		t.Fatalf("detail panel: %v", err)
	}
	if !strings.Contains(panel, "device:") || !strings.Contains(strings.ToLower(panel), "timeline") {
		t.Errorf("detail panel: %.300s", panel)
	}

	// Rename the device from its panel, then restore its automatic name.
	var renamed, restored string
	waitTitle := func(cond string) chromedp.Action {
		return chromedp.Poll(fmt.Sprintf(`(() => { const h = document.querySelector("#panel h2"); return h && h.textContent %s; })()`, cond), nil,
			chromedp.WithPollingTimeout(20*time.Second))
	}
	err = chromedp.Run(ctx,
		chromedp.WaitVisible(`#panel form.rename input`, chromedp.ByQuery),
		chromedp.SetValue(`#panel form.rename input`, "Lab <b>renamed</b>", chromedp.ByQuery),
		// A click, not chromedp.Submit: form.submit() skips the page's
		// submit handler.
		chromedp.Click(`#panel form.rename button[type=submit]`, chromedp.ByQuery),
		waitTitle(`=== "Lab <b>renamed</b>"`),
		chromedp.Text(`#panel h2`, &renamed, chromedp.ByQuery),
		shot("renamed"),
		chromedp.WaitVisible(`#panel form.rename [data-clear]`, chromedp.ByQuery),
		chromedp.Click(`#panel form.rename [data-clear]`, chromedp.ByQuery),
		waitTitle(`!== "Lab <b>renamed</b>"`),
		chromedp.Text(`#panel h2`, &restored, chromedp.ByQuery),
	)
	if err != nil {
		var out string
		_ = chromedp.Run(ctx, chromedp.Text(`#panel form.rename output`, &out, chromedp.ByQuery), shot("rename-failed"))
		t.Fatalf("rename: %v (form says %q)", err, out)
	}
	// The label is shown as text, never as markup.
	if renamed != "Lab <b>renamed</b>" || restored == "" {
		t.Errorf("renamed %q, restored %q", renamed, restored)
	}

	for i, tab := range []string{"devices", "flows", "dns", "facts", "sensors"} {
		var text string
		err := chromedp.Run(ctx,
			chromedp.Click(fmt.Sprintf(`.tabs button[data-tab="%s"]`, tab), chromedp.ByQuery),
			chromedp.WaitVisible(fmt.Sprintf(`#t-%s tbody`, tab), chromedp.ByQuery),
			chromedp.Text(fmt.Sprintf(`#t-%s`, tab), &text, chromedp.ByQuery),
			shot(fmt.Sprintf("%d-%s", i+1, tab)),
		)
		if err != nil {
			t.Fatalf("%s tab: %v", tab, err)
		}
		if strings.Contains(text, "Nothing in this window") {
			t.Errorf("%s tab is empty", tab)
		}
	}
	// Sort the connections by what the device sent, export them as CSV
	// (captured from the blob the page downloads), find the laptop by
	// name, and reopen its details from a link.
	var sortHead, hash, csv, found, deep string
	err = chromedp.Run(ctx,
		chromedp.Click(`.tabs button[data-tab="flows"]`, chromedp.ByQuery),
		chromedp.WaitVisible(`#t-flows tbody tr[data-i]`, chromedp.ByQuery),
		chromedp.Click(`#t-flows thead button.sort[data-col="8"]`, chromedp.ByQuery),
		chromedp.Text(`#t-flows thead th[aria-sort="descending"]`, &sortHead, chromedp.ByQuery),
		chromedp.Evaluate(`location.hash`, &hash),
		chromedp.Evaluate(`window.__csv = ""; { const create = URL.createObjectURL; URL.createObjectURL = (b) => { b.text().then((t) => { window.__csv = t; }); return create(b); }; } 0`, nil),
		chromedp.Click(`#tt-flows [data-csv]`, chromedp.ByQuery),
		chromedp.Poll(`window.__csv.length > 0`, nil, chromedp.WithPollingTimeout(10*time.Second)),
		chromedp.Evaluate(`window.__csv`, &csv),
		shot("flows-sorted"),
		chromedp.SendKeys(`#search`, "lab-lap", chromedp.ByQuery),
		chromedp.WaitVisible(`#search-results li[data-i]`, chromedp.ByQuery),
		chromedp.Text(`#search-results li[data-i]`, &found, chromedp.ByQuery),
		shot("search"),
	)
	if err != nil {
		t.Fatalf("sort, CSV and search: %v", err)
	}
	if !strings.HasPrefix(sortHead, "Sent") || !strings.Contains(hash, "sort=flows.8.desc") {
		t.Errorf("sorted by %q, hash %q", sortHead, hash)
	}
	if lines := strings.Split(strings.TrimSpace(csv), "\r\n"); len(lines) < 2 || !strings.HasPrefix(lines[0], "key,proto,client_ip") {
		t.Errorf("CSV: %.200q", csv)
	}
	if !strings.Contains(found, "lab-laptop") {
		t.Errorf("search found %q", found)
	}
	err = chromedp.Run(ctx,
		chromedp.SendKeys(`#search`, "\r", chromedp.ByQuery),
		chromedp.WaitVisible(`#panel h2`, chromedp.ByQuery),
		chromedp.Evaluate(`location.hash`, &hash),
	)
	if err != nil || !strings.Contains(hash, "open=device") {
		t.Fatalf("search result: %v, hash %q", err, hash)
	}
	err = chromedp.Run(ctx,
		chromedp.Evaluate(`document.querySelector("#panel").hidden = true; document.querySelector("#panel h2").textContent = ""`, nil),
		chromedp.Navigate(fmt.Sprintf("%s/#from=%d&to=%d&tab=devices&%s", ui, now-2*3600*1000, now+60*1000, hash[strings.Index(hash, "open="):])),
		chromedp.Reload(),
		chromedp.WaitVisible(`#panel h2`, chromedp.ByQuery),
		chromedp.Poll(`document.querySelector("#panel h2").textContent.length > 0`, nil, chromedp.WithPollingTimeout(20*time.Second)),
		chromedp.Text(`#panel h2`, &deep, chromedp.ByQuery),
	)
	if err != nil || !strings.Contains(deep, "lab-laptop") {
		t.Errorf("a link with open= showed %q: %v", deep, err)
	}

	// The lab has no history: the anomalies tab draws its table and says
	// it is learning.
	var learning string
	err = chromedp.Run(ctx,
		chromedp.Click(`.tabs button[data-tab="anomalies"]`, chromedp.ByQuery),
		chromedp.WaitVisible(`#t-anomalies thead`, chromedp.ByQuery),
		chromedp.Text(`#anomaly-note`, &learning, chromedp.ByQuery),
		shot("anomalies"),
	)
	if err != nil || !strings.Contains(learning, "Learning") {
		t.Errorf("anomalies tab: %v %q", err, learning)
	}

	// A browser with no stored token gets one shared dialog, and entering
	// the token recovers without a reload.
	if token != "" {
		err = chromedp.Run(ctx,
			chromedp.Navigate(ui+"/healthz"),
			chromedp.Evaluate(`localStorage.removeItem("netgraph.token")`, nil),
			chromedp.Navigate(fmt.Sprintf("%s/#from=%d&to=%d", ui, now-2*3600*1000, now+60*1000)),
			chromedp.WaitVisible(`#token-dialog[open]`, chromedp.ByQuery),
			chromedp.SendKeys(`#token-input`, token, chromedp.ByQuery),
			chromedp.Click(`#token-dialog button[value="ok"]`, chromedp.ByQuery),
			chromedp.WaitVisible(`#diagram svg`, chromedp.ByQuery),
			chromedp.Poll(`document.querySelector("#connect").hidden`, nil, chromedp.WithPollingTimeout(20*time.Second)),
			shot("token-recovered"),
		)
		if err != nil {
			t.Errorf("token dialog recovery: %v", err)
		}
	}

	if len(consoleErrors) > 0 {
		t.Errorf("page threw: %v", consoleErrors)
	}
}

// checkKeepsView pans the graph and checks that redrawing the same view
// keeps the pan: coming back from another tab redraws it, and switching
// Live off must not redraw at all. #graph-note is rewritten on every draw,
// so counting its mutations tells when a redraw has landed.
func checkKeepsView(t *testing.T, ctx context.Context) {
	t.Helper()
	const transform = `document.querySelector("#diagram svg").style.transform`
	const pan = `(() => { const el = document.querySelector("#diagram"); const r = el.getBoundingClientRect();
		const at = (type, d) => el.dispatchEvent(new PointerEvent(type, {bubbles: true, button: 0, pointerId: 1, clientX: r.left + 200 + d, clientY: r.top + 200 + d}));
		at("pointerdown", 0); at("pointermove", 60); at("pointerup", 60); })()`
	var draws int
	drawn := func(after *int) chromedp.Action {
		return chromedp.ActionFunc(func(ctx context.Context) error {
			return chromedp.Poll(fmt.Sprintf(`window.__draws > %d`, *after), nil, chromedp.WithPollingTimeout(30*time.Second)).Do(ctx)
		})
	}
	var panned, afterTab, livePanned, afterLive string
	var drawsBeforeOff, drawsAfterOff int
	err := chromedp.Run(ctx,
		chromedp.Evaluate(`window.__draws = 0; new MutationObserver(() => window.__draws++).observe(document.querySelector("#graph-note"), {childList: true}); 0`, nil),
		chromedp.Evaluate(pan, nil),
		chromedp.Evaluate(transform, &panned),
		chromedp.Click(`.tabs button[data-tab="devices"]`, chromedp.ByQuery),
		chromedp.WaitVisible(`#t-devices tbody`, chromedp.ByQuery),
		chromedp.Evaluate(`window.__draws`, &draws),
		chromedp.Click(`.tabs button[data-tab="graph"]`, chromedp.ByQuery),
		drawn(&draws),
		chromedp.Evaluate(transform, &afterTab),

		chromedp.Evaluate(`window.__draws`, &draws),
		chromedp.Click(`#live`, chromedp.ByQuery),
		drawn(&draws),
		chromedp.Evaluate(pan, nil),
		chromedp.Evaluate(transform, &livePanned),
		chromedp.Evaluate(`window.__draws`, &drawsBeforeOff),
		chromedp.Click(`#live`, chromedp.ByQuery),
		// Longer than Live's 2s debounce of ingest events.
		chromedp.Sleep(3*time.Second),
		chromedp.Evaluate(`window.__draws`, &drawsAfterOff),
		chromedp.Evaluate(transform, &afterLive),
	)
	if err != nil {
		t.Fatalf("keeping the view: %v", err)
	}
	if panned == "" || afterTab != panned {
		t.Errorf("redrawing the same graph refitted it: panned to %q, then %q", panned, afterTab)
	}
	if drawsAfterOff != drawsBeforeOff || afterLive != livePanned {
		t.Errorf("switching Live off redrew the graph (%d draws) or moved it: %q, then %q", drawsAfterOff-drawsBeforeOff, livePanned, afterLive)
	}
}

// TestWebUI checks a running server's UI: NETGRAPH_UI_URL (as the browser
// sees it), NETGRAPH_DEVTOOLS (a Chrome devtools endpoint, e.g.
// ws://127.0.0.1:9222), and optionally NETGRAPH_READ_TOKEN and
// NETGRAPH_SHOTS (a directory for screenshots).
func TestWebUI(t *testing.T) {
	ui, devtools := os.Getenv("NETGRAPH_UI_URL"), os.Getenv("NETGRAPH_DEVTOOLS")
	if ui == "" || devtools == "" {
		t.Skip("set NETGRAPH_UI_URL and NETGRAPH_DEVTOOLS")
	}
	checkWebUI(t, devtools, ui, os.Getenv("NETGRAPH_READ_TOKEN"), os.Getenv("NETGRAPH_SHOTS"), strings.Fields(os.Getenv("NETGRAPH_EXPECT")))
}
