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
			return os.WriteFile(fmt.Sprintf("%s/%s.png", shotDir, name), buf, 0o644)
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
	if len(consoleErrors) > 0 {
		t.Errorf("page threw: %v", consoleErrors)
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
