//go:build browser

package browser

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/xen0bit/netgraph/internal/agent"
	"github.com/xen0bit/netgraph/internal/model"
)

// A host agent's socket that matches one of the scenario's connections names
// its program: in the Connections table, and as a process the map can open.
func TestAgentProcessInTheUI(t *testing.T) {
	req, _ := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/flows?from=%d&to=%d&dir=out&limit=200", baseURL, dataEnd-2*3600_000, dataEnd), nil)
	req.Header.Set("Authorization", "Bearer "+readToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var flows []model.Flow
	err = json.NewDecoder(resp.Body).Decode(&flows)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	var fl model.Flow
	for _, f := range flows {
		if f.Proto == "tcp" && f.ClientPort > 0 && f.DeviceMAC != "" && f.Name != "" {
			fl = f
			break
		}
	}
	if fl.Key == "" {
		t.Fatalf("no outbound TCP connection with a name in %d flows", len(flows))
	}
	b, _ := json.Marshal(agent.Batch{Version: agent.Version, Agent: "journey-agent", Boot: "b", Seq: 1,
		Connections: []agent.Connection{{Key: "k", Proto: "tcp", LocalIP: fl.ClientIP, LocalPort: fl.ClientPort,
			RemoteIP: fl.ServerIP, RemotePort: fl.ServerPort, Direction: "out", PID: 4242, App: "journey-browser",
			Path: "/usr/bin/journey-browser", CodeID: "sha256:00", FirstSeen: fl.FirstSeen, LastSeen: fl.LastSeen}}})
	post, _ := http.NewRequest("POST", baseURL+"/api/v1/agent/events", bytes.NewReader(b))
	post.Header.Set("Authorization", "Bearer "+agentToken)
	post.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(post)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("agent events: %s", resp.Status)
	}

	s := open(t, window()+"&tab=flows&q="+url.QueryEscape("device:"+fl.DeviceMAC), "")
	s.waitFor("the program in the Connections table", `[...document.querySelectorAll("#table-body tr, table tr")].some((r) => r.textContent.includes("journey-browser") && r.textContent.includes("pid 4242"))`)

	proc := "process:" + fl.Device + "/journey-browser"
	s = open(t, window()+"&open="+url.QueryEscape(proc), "")
	s.waitFor("the process's details", `(() => { const p = document.querySelector("#panel-body"); return !!p && p.textContent.includes("A program on") && p.textContent.includes("journey-agent") && p.textContent.includes("/usr/bin/journey-browser"); })()`)
}

// The Processes tab lists what agents reported, a program seen only on
// loopback included, as text: a command line can say anything.
func TestProcessesTab(t *testing.T) {
	at := dataEnd - 30*60_000
	b, _ := json.Marshal(agent.Batch{Version: agent.Version, Agent: "proc-agent", Boot: "b", Seq: 1,
		Processes: []agent.Process{
			{PID: 10, PPID: 1, Path: "/usr/sbin/sshd", Cmdline: "sshd"},
			{PID: 7070, PPID: 10, Path: "/usr/bin/loopy", Cmdline: `loopy <img src=x onerror="window.pwned=1">`},
		},
		Connections: []agent.Connection{{Key: "lo", Proto: "tcp", LocalIP: "127.0.0.1", LocalPort: 45000,
			RemoteIP: "127.0.0.1", RemotePort: 6379, Direction: "local", PID: 7070, App: "loopy<b>x</b>",
			Path: "/usr/bin/loopy", FirstSeen: at, LastSeen: at + 1000}}})
	post, _ := http.NewRequest("POST", baseURL+"/api/v1/agent/events", bytes.NewReader(b))
	post.Header.Set("Authorization", "Bearer "+agentToken)
	post.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(post)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("agent events: %s", resp.Status)
	}
	s := open(t, window()+"&tab=processes", "")
	s.waitFor("the loopback program", `[...document.querySelectorAll("#t-processes tr")].some((r) => r.textContent.includes("loopy<b>x</b>") && r.textContent.includes("127.0.0.1:6379") && r.textContent.includes("sshd (10)"))`)
	var bad bool
	s.eval(`!!document.querySelector("#t-processes img, #t-processes b b") || !!window.pwned`, &bad)
	if bad {
		t.Fatal("a command line or program name became markup")
	}
	s.waitFor("a click on it", `(() => { const r = [...document.querySelectorAll("#t-processes tbody tr[data-i]")].find((r) => r.textContent.includes("loopy<b>x</b>")); if (r) r.click(); return !!r; })()`)
	s.waitFor("the program's details", `(() => { const p = document.querySelector("#panel-body"); return !!p && p.textContent.includes("No sensor saw") && p.textContent.includes("proc-agent"); })()`)
}
