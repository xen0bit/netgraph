//go:build js && wasm

// Command web is the browser half of the netgraph UI, compiled to WASM and
// served by `netgraph serve`. It runs in a Web Worker (web/src/worker.js)
// and exposes one entry point:
//
//	netgraphCall(method, requestJSON) -> Promise<responseJSON>
//
// Methods:
//
//	configure {base, token}            where the API is
//	graph     {query, theme, layout}   fetch a window's graph and draw it: {graph, svg}
//	render    {graph, theme, layout}   redraw a graph already fetched: {svg}
//	d2        {graph, theme}           the graph's d2 script: {script}
//	version                            {version}
//
// The graph is fetched with the same Go client the CLI uses (net/http runs
// on the browser's fetch here) and laid out with the same d2 code the
// server and TUI use; only the drawing happens in the browser.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"syscall/js"
	"time"

	"github.com/xen0bit/netgraph/internal/apiclient"
	"github.com/xen0bit/netgraph/internal/buildinfo"
	"github.com/xen0bit/netgraph/internal/graph"
	"github.com/xen0bit/netgraph/internal/graph/d2render"
	"github.com/xen0bit/netgraph/internal/model"
)

var client = apiclient.NewClient("", "")

func main() {
	js.Global().Set("netgraphCall", js.FuncOf(call))
	js.Global().Set("netgraphVersion", buildinfo.Version)
	if ready := js.Global().Get("netgraphReady"); ready.Type() == js.TypeFunction {
		ready.Invoke(buildinfo.Version)
	}
	select {}
}

// call returns a Promise and does the work on its own goroutine: a JS
// callback must not block, and fetch needs the event loop to make progress.
func call(_ js.Value, args []js.Value) any {
	method, req := "", "{}"
	if len(args) > 0 {
		method = args[0].String()
	}
	if len(args) > 1 && args[1].Type() == js.TypeString {
		req = args[1].String()
	}
	return js.Global().Get("Promise").New(js.FuncOf(func(_ js.Value, p []js.Value) any {
		resolve := p[0]
		go func() {
			out, err := dispatch(method, []byte(req))
			if err != nil {
				out = errorJSON(err)
			}
			resolve.Invoke(out)
		}()
		return nil
	}))
}

func dispatch(method string, req []byte) (s string, err error) {
	// A panic would kill the Go runtime and every later call from the page.
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%s: %v", method, r)
		}
	}()
	var in struct {
		Base   string       `json:"base"`
		Token  string       `json:"token"`
		Query  string       `json:"query"`
		Theme  string       `json:"theme"`
		Layout string       `json:"layout"`
		Graph  *model.Graph `json:"graph"`
	}
	if err := json.Unmarshal(req, &in); err != nil {
		return "", fmt.Errorf("%s: bad request: %w", method, err)
	}
	ro := d2render.Options{Theme: in.Theme, Layout: in.Layout}
	switch method {
	case "version":
		return marshal(map[string]string{"version": buildinfo.Version})
	case "configure":
		client = apiclient.NewClient(in.Base, in.Token)
		return marshal(map[string]bool{"ok": true})
	case "graph":
		q, err := url.ParseQuery(in.Query)
		if err != nil {
			return "", err
		}
		f, err := model.ParseFilter(q, time.Now())
		if err != nil {
			return "", err
		}
		g, err := client.Graph(context.Background(), f, model.ParseGraphOptions(q))
		if err != nil {
			return "", err
		}
		svg, err := d2render.SVG(g, ro)
		if err != nil {
			return "", err
		}
		return marshal(map[string]any{"graph": g, "svg": string(svg)})
	case "render":
		if in.Graph == nil {
			return "", errors.New("render: no graph")
		}
		svg, err := d2render.SVG(in.Graph, ro)
		if err != nil {
			return "", err
		}
		return marshal(map[string]string{"svg": string(svg)})
	case "d2":
		if in.Graph == nil {
			return "", errors.New("d2: no graph")
		}
		return marshal(map[string]string{"script": graph.RenderD2(in.Graph, graph.RenderOptions{Theme: in.Theme})})
	}
	return "", fmt.Errorf("unknown method %q", method)
}

func marshal(v any) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}

func errorJSON(err error) string {
	b, _ := json.Marshal(map[string]string{"error": err.Error()})
	return string(b)
}
