//go:build browser

package browser

import (
	"strconv"
	"testing"

	"github.com/chromedp/chromedp"
)

func TestSensorSettings(t *testing.T) {
	s := open(t, "tab=sensors", "")
	s.waitFor("the sensor table", `!!document.querySelector("#t-sensors tbody tr[data-i]")`)
	s.waitFor("a status", `!!document.querySelector("#t-sensors tbody .badge")`)
	s.run(chromedp.Click(`#t-sensors tbody tr[data-i]`, chromedp.ByQuery))
	s.waitFor("its panel", `!document.querySelector("#panel").hidden && document.querySelector("#panel-body").textContent.includes("Settings")`)
	s.waitFor("the form", `!!document.querySelector("#panel-body [data-fleet-form]")`)
	s.run(chromedp.SetValue(`#panel-body input[name="flush_s"]`, "9", chromedp.ByQuery))
	s.run(chromedp.Click(`#panel-body [data-fleet-form] button[type="submit"]`, chromedp.ByQuery))
	s.waitFor("it saved", `document.querySelector("#panel-body [data-fleet-said]")?.textContent.includes("Saved")`)

	// Settings for every sensor have their own panel.
	s.run(chromedp.Click(`#panel-body [data-fleet-all]`, chromedp.ByQuery))
	s.waitFor("the fleet's panel", `document.querySelector("#panel-body").textContent.includes("All sensors")`)
	s.run(chromedp.SetValue(`#panel-body input[name="active_timeout_s"]`, "45", chromedp.ByQuery))
	s.run(chromedp.Click(`#panel-body [data-fleet-form] button[type="submit"]`, chromedp.ByQuery))
	s.waitFor("it saved", `document.querySelector("#panel-body [data-fleet-said]")?.textContent.includes("Saved")`)
	// And reading them back shows what was saved.
	s.run(chromedp.Click(`#t-sensors tbody tr[data-i]`, chromedp.ByQuery))
	s.waitFor("back on the sensor", `!!document.querySelector('#panel-body input[name="flush_s"]')`)
	s.run(chromedp.Click(`#panel-body [data-fleet-all]`, chromedp.ByQuery))
	s.waitFor("what was saved", `document.querySelector('#panel-body input[name="active_timeout_s"]')?.value === "45"`)
	// Clean up for the tests after this one, which share a database.
	s.run(chromedp.SetValue(`#panel-body input[name="active_timeout_s"]`, "", chromedp.ByQuery))
	s.run(chromedp.Click(`#panel-body [data-fleet-form] button[type="submit"]`, chromedp.ByQuery))
	s.waitFor("cleared", `document.querySelector("#panel-body [data-fleet-said]")?.textContent.includes("Saved")`)
}

// What a sensor calls itself is its own to choose, so it's text.
func TestSensorDetailIsText(t *testing.T) {
	s := open(t, "tab=sensors", "")
	s.waitFor("the sensor table", `!!document.querySelector("#t-sensors tbody tr[data-i]")`)
	var injected bool
	s.run(chromedp.Evaluate(`import("/js/fleet.js").then((m) => {
		const box = document.createElement("div");
		const bad = "<img src=x onerror=window.pwned=1>";
		box.innerHTML = m.sensorDetail({name: bad, version: bad, os: bad, arch: bad, status: bad, problems: [bad], upgrade_to: bad, settable: true, takes_config: true, config: {log_level: bad}, in_effect: {log_level: bad, active_timeout_s: bad}});
		return !!box.querySelector("img");
	})`, &injected, awaitPromise))
	if injected {
		t.Error("a sensor's own words became markup")
	}
}

// Network names are whatever anyone nearby chooses to broadcast.
func TestAirspace(t *testing.T) {
	s := open(t, window()+"&tab=airspace", "")
	s.waitFor("the empty state", `document.querySelector("#airspace-body").textContent.includes("monitor-mode")`)
	var out struct {
		Injected bool `json:"injected"`
		Bars     int  `json:"bars"`
		Advice   bool `json:"advice"`
		Rows     int  `json:"rows"`
	}
	s.run(chromedp.Evaluate(`import("/js/airspace.js").then((m) => {
		const bad = "<img src=x onerror=window.pwned=1>";
		const box = document.createElement("div");
		box.innerHTML = m.airspaceHTML({
			networks: [
				{ssid: bad, bssid: bad, security: bad, band: bad, channel: 1, signal: -40, clients: [bad], rogue: true, last_seen: Date.now()},
				{ssid: "", bssid: "02:00:00:00:00:02", band: "2.4 GHz", channel: 3, signal: 0, last_seen: Date.now()},
			],
			channels: [
				{band: "2.4 GHz", channel: 1, networks: 1, clients: 1, strongest: -40, overlapping: 1},
				{band: "2.4 GHz", channel: 3, networks: 1, clients: 0, overlapping: 1},
				{band: bad, channel: 36, networks: 1, clients: 0},
			],
			gaps: [bad],
		});
		return {injected: !!box.querySelector("img"), bars: box.querySelectorAll(".air-bar").length, advice: box.textContent.includes("has the fewest"), rows: box.querySelectorAll("tbody tr").length};
	})`, &out, awaitPromise))
	if out.Injected {
		t.Error("a network's name became markup")
	}
	if out.Bars != 3 || !out.Advice || out.Rows != 2 {
		t.Errorf("%+v", out)
	}
}

// Click a connection on the map, deny it, and the policy says what would stop.
func TestPolicyFromTheMap(t *testing.T) {
	s := open(t, window(), "")
	s.run(chromedp.Evaluate(`localStorage.removeItem("netgraph.policy.draft")`, nil))
	s.waitFor("the map", nodesDrawn)
	s.settle()
	s.waitFor("edges to be placed", `[...document.querySelector("#diagram").__map.edges.values()].some((d) => d.c)`)
	x, y := s.point(edgePoint)
	s.run(chromedp.MouseClickXY(x, y))
	s.waitFor("the edge panel", `!!document.querySelector('#panel-body [data-policy="deny"]')`)
	s.run(chromedp.Click(`#panel-body [data-policy="deny"]`, chromedp.ByQuery))
	s.waitFor("it to say what stops", `document.querySelector("#status").textContent.includes("in the policy")`)
	s.run(chromedp.Evaluate(`document.querySelector('[data-tab="findings"]')?.click()`, nil))
	s.waitFor("Policy under Findings", `!!document.querySelector('#subtabs [data-tab="policy"]')`)
	s.run(chromedp.Click(`#subtabs [data-tab="policy"]`, chromedp.ByQuery))
	s.waitFor("the rule", `document.querySelector('#policy-body tr[data-rule] [data-r="action"]')?.value === "deny"`)
	s.waitFor("the impact", `/\d+ blocked/.test(document.querySelector("#policy-impact").textContent)`)
	var blocked float64
	s.eval(`Number(/(\d+) blocked/.exec(document.querySelector("#policy-impact").textContent)[1])`, &blocked)
	if blocked == 0 {
		t.Error("denying a connection on the map stopped nothing")
	}
	// Changing it re-simulates, and the draft survives a reload.
	s.run(chromedp.SetValue(`#policy-body tr[data-rule] [data-r="action"]`, "allow", chromedp.ByQuery))
	s.eval(`document.querySelector('#policy-body tr[data-rule] [data-r="action"]').dispatchEvent(new Event("change", {bubbles: true}))`, nil)
	s.waitFor("the impact to change", `/^0 blocked/.test(document.querySelector("#policy-impact").textContent)`)
	s.run(chromedp.Reload())
	s.waitFor("the draft back", `document.querySelector('#policy-body tr[data-rule] [data-r="action"]')?.value === "allow"`)
	s.run(chromedp.Click(`[data-policy-clear]`, chromedp.ByQuery))
	s.waitFor("it cleared", `!document.querySelector('#policy-body tr[data-rule]')`)
}

func TestPolicyLearnAndExport(t *testing.T) {
	s := open(t, window()+"&tab=policy", "")
	s.run(chromedp.Evaluate(`localStorage.removeItem("netgraph.policy.draft")`, nil))
	s.run(chromedp.Reload())
	s.waitFor("the builder", `document.querySelectorAll('#policy-learn option').length > 1`)
	s.run(chromedp.Evaluate(`(() => {
		const sel = document.querySelector('#policy-learn select');
		sel.value = [...sel.options].find((o) => o.value.includes("3c:22:fb")).value;
	})()`, nil))
	s.run(chromedp.Click(`#policy-learn button[type="submit"]`, chromedp.ByQuery))
	s.waitFor("what it learned", `document.querySelectorAll('#policy-body tr[data-rule]').length > 0 && document.querySelector("#policy-gaps").textContent.includes("connections")`)
	s.waitFor("the simulation", `/\d+ blocked/.test(document.querySelector("#policy-impact").textContent)`)
	var egress string
	s.eval(`document.querySelector('[data-p="egress"]').value`, &egress)
	if egress != "deny" {
		t.Errorf("learned, but the default is %q", egress)
	}
	for _, c := range []struct{ format, want string }{
		{"nftables", "table inet netgraph"}, {"openwrt", "config rule"}, {"opnsense", "<filter>"},
	} {
		s.run(chromedp.SetValue(`[data-p="format"]`, c.format, chromedp.ByQuery))
		s.run(chromedp.Click(`[data-policy-export]`, chromedp.ByQuery))
		s.waitFor(c.format, `document.querySelector("#policy-config").value.includes(`+strconv.Quote(c.want)+`)`)
	}
	// Editing after exporting mustn't leave a stale export on screen.
	s.run(chromedp.Evaluate(`(() => { const e = document.querySelector('[data-p="ingress"]'); e.value = "allow"; e.dispatchEvent(new Event("change", {bubbles: true})); })()`, nil))
	s.waitFor("the old export gone", `document.querySelector("#policy-config").hidden`)
	s.run(chromedp.Click(`[data-policy-clear]`, chromedp.ByQuery))
}

// A device's label reaches the page in the policy too.
func TestPolicyIsText(t *testing.T) {
	s := open(t, window()+"&tab=policy", "")
	s.waitFor("the builder", `!!document.querySelector("#policy-learn")`)
	var injected bool
	s.run(chromedp.Evaluate(`import("/js/policy.js").then((m) => {
		const bad = '"><img src=x onerror=window.pwned=1>';
		const box = document.createElement("div");
		const p = m.emptyPolicy();
		p.rules = [{name: bad, from: bad, to: bad, ports: [bad], action: "deny"}];
		box.innerHTML = m.policyHTML(p, [{id: bad, label: bad, ips: [bad]}]) + m.impactHTML({summary: {}, blocked: [{device_name: bad, destination: bad, port: bad, reason: bad, rule: bad}], gaps: [bad]});
		return !!box.querySelector("img");
	})`, &injected, awaitPromise))
	if injected {
		t.Error("a label became markup")
	}
	// A rule it can't name precisely isn't made broader instead.
	var made bool
	s.run(chromedp.Evaluate(`import("/js/policy.js").then((m) => {
		const p = m.emptyPolicy();
		return m.addEdge(p, {from: "device:aa:bb:cc:00:00:01", to: "others:rest"}, "deny", (x) => x) !== null || p.rules.length > 0 || p.zones.length > 0;
	})`, &made, awaitPromise))
	if made {
		t.Error("a rule was made for an end it can't name")
	}
}

func TestSettingsSaysAboutTheArchive(t *testing.T) {
	s := open(t, "tab=settings", "")
	s.waitFor("what it says", `document.querySelector("#settings-archive")?.textContent.startsWith("Off.")`)
}
