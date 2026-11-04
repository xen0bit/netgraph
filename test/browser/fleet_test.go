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
