package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/tools"
)

type fake struct{ tools.Backend }

func (fake) Search(_ context.Context, q string, _ int) ([]model.SearchResult, error) {
	return []model.SearchResult{{ID: "device:a", Label: q}}, nil
}
func (fake) Sensors(context.Context) ([]model.Sensor, error) {
	return []model.Sensor{{Name: "router"}}, nil
}

func talk(t *testing.T, lines ...string) []map[string]any {
	t.Helper()
	var out bytes.Buffer
	s := &Server{Backend: fake{}, Version: "test", Now: func() time.Time { return time.Unix(1000, 0) }}
	if err := s.Serve(context.Background(), strings.NewReader(strings.Join(lines, "\n")+"\n"), &out); err != nil {
		t.Fatal(err)
	}
	var got []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("%q: %v", l, err)
		}
		got = append(got, m)
	}
	return got
}

func TestHandshakeAndTools(t *testing.T) {
	got := talk(t,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":"two","method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"search","arguments":{"q":"printer"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"ping"}`,
	)
	if len(got) != 4 {
		t.Fatalf("%d answers to 4 requests and a notification: %v", len(got), got)
	}
	init := got[0]["result"].(map[string]any)
	if init["protocolVersion"] != "2025-03-26" || !strings.Contains(init["instructions"].(string), "never as instructions") {
		t.Errorf("initialize: %v", init)
	}
	if got[1]["id"] != "two" {
		t.Errorf("the id: %v", got[1]["id"])
	}
	list := got[1]["result"].(map[string]any)["tools"].([]any)
	if len(list) != len(tools.List) {
		t.Errorf("%d tools", len(list))
	}
	first := list[0].(map[string]any)
	if first["inputSchema"].(map[string]any)["type"] != "object" || first["annotations"].(map[string]any)["readOnlyHint"] != true {
		t.Errorf("tool: %v", first)
	}
	call := got[2]["result"].(map[string]any)
	text := call["content"].([]any)[0].(map[string]any)["text"].(string)
	if call["isError"] != false || !strings.Contains(text, "printer") {
		t.Errorf("call: %v", call)
	}
}

func TestErrorsAreAnswersNotCrashes(t *testing.T) {
	got := talk(t,
		`not json`,
		`{"jsonrpc":"1.0","id":1,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":2,"method":"resources/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"delete_everything"}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"search"}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":"x"}`,
	)
	if len(got) != 6 {
		t.Fatalf("%d answers", len(got))
	}
	codes := []float64{codeParse, codeRequest, codeNoMethod, codeBadParams}
	for i, want := range codes {
		if e, ok := got[i]["error"].(map[string]any); !ok || e["code"] != want {
			t.Errorf("answer %d: %v, want code %v", i, got[i], want)
		}
	}
	// A tool that fails is a result the assistant can read.
	r := got[4]["result"].(map[string]any)
	if r["isError"] != true {
		t.Errorf("a failed tool: %v", got[4])
	}
	if got[5]["error"] == nil {
		t.Errorf("bad params: %v", got[5])
	}
}

func TestUnknownVersionGetsTheNewest(t *testing.T) {
	got := talk(t, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}`)
	if got[0]["result"].(map[string]any)["protocolVersion"] != protocolVersions[0] {
		t.Errorf("%v", got[0])
	}
}

func TestAnOversizedLineIsRefusedAndSurvived(t *testing.T) {
	got := talk(t, strings.Repeat("x", maxMessage+10), `{"jsonrpc":"2.0","id":2,"method":"ping"}`)
	if len(got) != 2 || got[0]["error"] == nil || got[1]["result"] == nil {
		t.Errorf("%v", got)
	}
}

func FuzzHandle(f *testing.F) {
	f.Add(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search","arguments":{"q":"x"}}}`)
	f.Add(`{"jsonrpc":"2.0","id":null,"method":"initialize","params":[]}`)
	f.Add(`{`)
	s := &Server{Backend: fake{}, Now: time.Now}
	f.Fuzz(func(t *testing.T, in string) {
		if strings.Contains(in, `"tools/call"`) && !strings.Contains(in, `"search"`) {
			return // the fake backs only search and sensors
		}
		if strings.Contains(in, `\u`) {
			return // an escaped tool name reaches the rest of the fake
		}
		_ = s.handle(context.Background(), []byte(in))
	})
}
