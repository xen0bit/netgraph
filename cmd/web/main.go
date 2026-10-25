//go:build js && wasm

// Command web is the browser half of the netgraph UI, compiled to WASM and
// served by `netgraph serve`. It runs in a Web Worker (web/src/worker.js) and
// exposes one entry point, netgraphCall(method, requestJSON) -> responseJSON,
// so the page talks to it exactly as it would to any RPC.
package main

import (
	"encoding/json"
	"fmt"
	"syscall/js"

	"github.com/xen0bit/netgraph/internal/buildinfo"
)

func main() {
	js.Global().Set("netgraphCall", js.FuncOf(call))
	js.Global().Set("netgraphVersion", buildinfo.Version)
	if ready := js.Global().Get("netgraphReady"); ready.Type() == js.TypeFunction {
		ready.Invoke(buildinfo.Version)
	}
	select {}
}

func call(_ js.Value, args []js.Value) (result any) {
	// A panic would kill the Go runtime and with it every later call from the
	// page, so it becomes an error response instead.
	defer func() {
		if r := recover(); r != nil {
			result = errorJSON(fmt.Sprint(r))
		}
	}()
	if len(args) < 1 {
		return errorJSON("netgraphCall: missing method")
	}
	switch method := args[0].String(); method {
	case "version":
		b, _ := json.Marshal(map[string]string{"version": buildinfo.Version})
		return string(b)
	default:
		return errorJSON("netgraphCall: unknown method " + method)
	}
}

func errorJSON(msg string) string {
	b, _ := json.Marshal(map[string]string{"error": msg})
	return string(b)
}
