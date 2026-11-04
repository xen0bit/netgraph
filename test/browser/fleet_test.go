//go:build browser

package browser

import (
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
