// Sensors: how each is doing, whether it's behind the server, and what's asked of it.
// Names and versions come from the sensors themselves, so they go through esc().
import { esc, ago } from "./util.js";

const statusText = { ok: "Reporting", quiet: "Quiet", struggling: "Struggling" };
const statusClass = { ok: "sev-low", quiet: "sev-medium", struggling: "sev-high" };

export const sensorStatus = (s) => {
  const state = `<span class="badge ${statusClass[s.status] || ""}">${esc(statusText[s.status] || s.status || "")}</span>`;
  return s.upgrade_to ? `${state} <span class="badge" title="${esc(`The server is on ${s.upgrade_to}`)}">Upgrade</span>` : state;
};

const num = (v) => (v ? String(v) : "");

function settingsForm(values, inEffect) {
  const o = values || {};
  const rdns = o.rdns === undefined || o.rdns === null ? "" : String(o.rdns);
  const hint = (v) => (v === undefined || v === null || v === "" ? "" : `<span class="muted">now ${esc(v)}</span>`);
  return `<form class="fleet-settings" data-fleet-form>
    <label>Log level <select name="log_level">
      ${[["", "Leave as started"], ["debug", "debug"], ["info", "info"], ["warn", "warn"], ["error", "error"]].map(([v, t]) => `<option value="${v}" ${o.log_level === v || (!o.log_level && !v) ? "selected" : ""}>${t}</option>`).join("")}
    </select> ${hint(inEffect?.log_level)}</label>
    <label>Reverse DNS <select name="rdns">
      ${[["", "Leave as started"], ["true", "On"], ["false", "Off"]].map(([v, t]) => `<option value="${v}" ${rdns === v ? "selected" : ""}>${t}</option>`).join("")}
    </select> ${hint(inEffect?.rdns === undefined ? "" : inEffect.rdns ? "on" : "off")}</label>
    <label>Seconds between records of a long flow <input name="active_timeout_s" type="number" min="5" max="600" value="${num(o.active_timeout_s)}" placeholder="as started"> ${hint(inEffect?.active_timeout_s)}</label>
    <label>Seconds between batches <input name="flush_s" type="number" min="1" max="60" value="${num(o.flush_s)}" placeholder="as started"> ${hint(inEffect?.flush_s)}</label>
    <button type="submit">Save</button> <span class="muted" data-fleet-said role="status"></span>
  </form>`;
}

export function readSettings(form) {
  const f = new FormData(form);
  const out = {};
  if (f.get("log_level")) out.log_level = f.get("log_level");
  if (f.get("rdns")) out.rdns = f.get("rdns") === "true";
  if (f.get("active_timeout_s")) out.active_timeout_s = Number(f.get("active_timeout_s"));
  if (f.get("flush_s")) out.flush_s = Number(f.get("flush_s"));
  return out;
}

// fleetSettingsHTML is the panel for what's asked of every sensor.
export function fleetSettingsHTML(values) {
  return `<h2>All sensors</h2>
    <p class="muted">Sensors ask for these every minute, and keep them in memory only. A sensor's own settings override them. Nothing here can run anything on a sensor, or change where it sends data.</p>
    ${settingsForm(values)}`;
}

// sensorDetail is one sensor, in the details panel.
export function sensorDetail(s) {
  const when = s.last_seen ? ago(Date.now() - s.last_seen) : "never";
  const problems = (s.problems || []).map((p) => `<li>${esc(p)}</li>`).join("");
  const platform = [s.os, s.arch].filter(Boolean).join("/");
  const upgrade = s.upgrade_to
    ? `<h3>Upgrade available</h3><p>This sensor runs <b>${esc(s.version)}</b> and the server <b>${esc(s.upgrade_to)}</b>. Install the ${esc(platform || "matching")} build of netgraph-sensor from the release page, then restart it. netgraph won't change software on a router by itself.</p>`
    : "";
  let settings = `<p class="muted">This source runs inside the server, so it has nothing to set.</p>`;
  if (s.settable) {
    settings = s.takes_config
      ? `<p class="muted">${s.config_applied ? "It's doing what's asked." : "It hasn't picked this up yet: sensors ask every minute."} Empty leaves the setting as the sensor started, or as set for all sensors.</p>${settingsForm(s.config, s.in_effect)}`
      : `<p class="muted">This sensor doesn't take settings from the server: it's too old, or started with <code>-remote-config=false</code>. Saved settings apply if that changes.</p>${settingsForm(s.config)}`;
  }
  return `<h2>${esc(s.name)}</h2>
    <p>${sensorStatus(s)} <span class="muted">${esc(s.version || "")}${platform ? ` · ${esc(platform)}` : ""} · last heard ${esc(when)}</span></p>
    ${problems ? `<h3>What's wrong now</h3><ul class="tight">${problems}</ul>` : ""}
    ${upgrade}
    <h3>Settings</h3>${settings}
    <p><button type="button" data-fleet-all>Settings for all sensors</button></p>`;
}
