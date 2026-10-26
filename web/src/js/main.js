// netgraph web UI. Tables and the timeline come straight from the JSON API;
// the graph is fetched, laid out and drawn by the WASM engine in a worker,
// falling back to the server's SVG if WASM cannot load.
import { Engine } from "./engine.js";
import { Diagram } from "./diagram.js";

const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];

// Everything shown here can come off the network — hostnames, user agents,
// UPnP strings — so every value goes through esc() or textContent.
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

const units = { s: 1e3, m: 6e4, h: 36e5, d: 864e5, w: 6048e5 };
const parseSpan = (s) => { const m = /^(\d+(?:\.\d+)?)([smhdw])$/.exec(s); return m ? Number(m[1]) * units[m[2]] : null; };
const fmtSpan = (ms) => {
  for (const [u, v] of [["w", units.w], ["d", units.d], ["h", units.h], ["m", units.m], ["s", units.s]]) {
    if (ms >= v && ms % v === 0) return `${ms / v}${u}`;
  }
  return `${Math.round(ms / 1000)}s`;
};
const bytes = (n) => {
  n = Number(n || 0);
  if (n < 1000) return `${n}B`;
  const u = ["kB", "MB", "GB", "TB", "PB"];
  let i = -1;
  do { n /= 1000; i++; } while (n >= 1000 && i < u.length - 1);
  return `${n >= 100 ? n.toFixed(0) : n.toFixed(1)}${u[i]}`;
};
const pad2 = (n) => String(n).padStart(2, "0");
const clock = (ms) => { const d = new Date(ms); return `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`; };
const stamp = (ms) => { const d = new Date(ms); return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ${clock(ms)}`; };
const toLocalInput = (ms) => { const d = new Date(ms); return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}T${clock(ms)}`; };

// --- state ------------------------------------------------------------------

const state = {
  to: Date.now(),
  span: units.h,
  live: false,
  filter: "",
  tab: "graph",
  gopts: { collapse: true, dns: true, identity: false, top: 15 },
  // dagre runs inside the WASM engine; d2's ELK needs a host-provided
  // synchronous ELK in the browser, so "elk" is drawn by the server.
  layout: "dagre",
  graph: null,
  data: {},
};

function loadHash() {
  const p = new URLSearchParams(location.hash.slice(1));
  if (p.get("to")) state.to = Number(p.get("to"));
  if (p.get("span")) state.span = Number(p.get("span"));
  if (p.get("from") && p.get("to")) state.span = state.to - Number(p.get("from"));
  state.live = p.get("live") === "1" || !p.has("to");
  state.filter = p.get("q") || "";
  if (p.get("tab")) state.tab = p.get("tab");
  for (const k of ["collapse", "dns", "identity"]) if (p.has(k)) state.gopts[k] = p.get(k) === "1";
  if (p.has("top")) state.gopts.top = Number(p.get("top"));
}

function saveHash() {
  const p = new URLSearchParams();
  if (state.live) { p.set("live", "1"); p.set("span", state.span); } else { p.set("from", state.to - state.span); p.set("to", state.to); }
  if (state.filter) p.set("q", state.filter);
  if (state.tab !== "graph") p.set("tab", state.tab);
  for (const k of ["collapse", "dns", "identity"]) p.set(k, state.gopts[k] ? "1" : "0");
  p.set("top", state.gopts.top);
  lastHash = p.toString();
  history.replaceState(null, "", "#" + lastHash);
}

let lastHash = "";

// parseFilter turns "device:x domain:y word" into API parameters; a bare
// word is a domain, an IPv6 address an ip, a MAC a device.
function parseFilter(s) {
  const out = {};
  for (const tok of s.trim().split(/\s+/).filter(Boolean)) {
    const i = tok.indexOf(":");
    const k = i > 0 ? tok.slice(0, i) : "";
    const v = tok.slice(i + 1);
    if (["device", "ip", "domain", "port", "proto", "app", "multicast"].includes(k)) out[k] = v;
    else if (/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(tok)) out.device = tok;
    else if (tok.split(":").length > 2) out.ip = tok;
    else out.domain = tok;
  }
  return out;
}

function params(extra = {}) {
  const p = new URLSearchParams({ from: state.to - state.span, to: state.to, ...parseFilter(state.filter), ...extra });
  return p;
}

// --- API ----------------------------------------------------------------------

let token = localStorage.getItem("netgraph.token") || "";

async function api(path, extra = {}, raw = false) {
  for (;;) {
    const headers = token ? { Authorization: `Bearer ${token}` } : {};
    const resp = await fetch(`/api/v1/${path}?${params(extra)}`, { headers });
    if (resp.status === 401) { await askToken(); continue; }
    if (!resp.ok) {
      let msg = resp.statusText;
      try { msg = (await resp.json()).error || msg; } catch { /* not JSON */ }
      throw new Error(`${path}: ${msg}`);
    }
    return raw ? resp.text() : resp.json();
  }
}

function askToken() {
  const dlg = $("#token-dialog");
  return new Promise((resolve) => {
    dlg.addEventListener("close", () => {
      token = $("#token-input").value.trim();
      try { localStorage.setItem("netgraph.token", token); } catch { /* private mode */ }
      engine?.call("configure", { base: location.origin, token }).catch(() => {});
      resolve();
    }, { once: true });
    dlg.showModal();
  });
}

// --- status -------------------------------------------------------------------

let busy = 0;
function setStatus(text, err = false) {
  const el = $("#status");
  el.textContent = text;
  el.className = err ? "err" : "";
}
async function track(p) {
  busy++;
  setStatus("loading…");
  try {
    const v = await p;
    if (--busy === 0) setStatus(`updated ${clock(Date.now())}`);
    return v;
  } catch (e) {
    busy--;
    setStatus(e.message, true);
    throw e;
  }
}

// --- window controls ------------------------------------------------------------

function renderWindow() {
  $("#from").value = toLocalInput(state.to - state.span);
  $("#to").value = toLocalInput(state.to);
  $("#live").setAttribute("aria-pressed", String(state.live));
  for (const b of $$(".presets button")) b.classList.toggle("on", parseSpan(b.dataset.span) === state.span);
}

function setWindow(to, span, { live = false } = {}) {
  state.to = Math.round(to);
  state.span = Math.max(Math.round(span), 10_000);
  state.live = live;
  refresh();
}

// --- refresh ------------------------------------------------------------------

let refreshSeq = 0;
async function refresh() {
  if (state.live) state.to = Date.now();
  saveHash();
  renderWindow();
  const seq = ++refreshSeq;
  const cols = Math.max(Math.floor($("#spark").clientWidth / 3), 30);
  const step = Math.max(Math.floor(state.span / cols / 1000), 1) + "s";
  const [summary, series] = await Promise.all([
    track(api("summary")).catch(() => null),
    track(api("timeseries", { step })).catch(() => null),
  ]);
  if (seq !== refreshSeq) return;
  renderSummary(summary);
  renderSpark(series);
  await renderTab(seq);
}

async function renderTab(seq) {
  const t = state.tab;
  try {
    if (t === "graph") return await renderGraph(seq);
    const path = { devices: "devices", flows: "flows", dns: "dns", facts: "facts", wifi: "wifi", sensors: "sensors" }[t];
    const rows = await track(api(path));
    if (seq !== refreshSeq) return;
    state.data[t] = rows || [];
    renderTable(t);
  } catch { /* status shows it */ }
}

function renderSummary(s) {
  const el = $("#summary");
  if (!s) { el.textContent = ""; return; }
  el.innerHTML = [
    `<span><b>${s.devices}</b> devices</span>`,
    `<span><b>${s.flows}</b> connections (peak <b>${s.peak_connections}</b>)</span>`,
    `<span><b>${s.dns_queries}</b> lookups of <b>${s.domains}</b> names</span>`,
    `<span>↑ <b>${bytes(s.bytes_out)}</b> ↓ <b>${bytes(s.bytes_in)}</b></span>`,
    s.precision === "hour" ? `<span class="hour" title="Older than raw retention: answered from hourly rollups">hourly precision</span>` : "",
  ].join("");
}

// --- timeline ------------------------------------------------------------------

let series = null;
function renderSpark(s) {
  series = s;
  const c = $("#spark");
  const dpr = window.devicePixelRatio || 1;
  c.width = c.clientWidth * dpr;
  c.height = c.clientHeight * dpr;
  const g = c.getContext("2d");
  g.scale(dpr, dpr);
  const W = c.clientWidth, H = c.clientHeight;
  g.clearRect(0, 0, W, H);
  if (!s || !s.buckets?.length) { $("#spark-label").textContent = ""; return; }
  const from = state.to - state.span;
  const x = (t) => ((t - from) / state.span) * W;
  const peak = Math.max(1, ...s.buckets.map((b) => b.bytes_in + b.bytes_out));
  const css = getComputedStyle(document.documentElement);
  g.fillStyle = css.getPropertyValue("--accent").trim() || "#2563eb";
  for (const b of s.buckets) {
    const v = b.bytes_in + b.bytes_out;
    if (!v) continue;
    const h = Math.max(1, (v / peak) * (H - 6));
    const x0 = x(b.ts), x1 = x(b.ts + s.step);
    g.fillRect(Math.max(x0, 0), H - h, Math.max(x1 - x0 - 0.5, 1), h);
  }
  g.fillStyle = css.getPropertyValue("--fg-2").trim() || "#888";
  g.font = "11px system-ui";
  g.fillText(stamp(from), 4, 12);
  const end = stamp(state.to);
  g.fillText(end, W - g.measureText(end).width - 4, 12);
  $("#spark-label").textContent = `peak ${bytes(peak)} per ${fmtSpan(s.step)} · ${s.precision}`;
}

function brush() {
  const c = $("#spark");
  let start = null;
  const at = (e) => (e.clientX - c.getBoundingClientRect().left) / c.clientWidth;
  c.addEventListener("pointerdown", (e) => {
    start = at(e);
    try { c.setPointerCapture(e.pointerId); } catch { /* synthetic pointer */ }
  });
  c.addEventListener("pointermove", (e) => {
    if (start === null) return;
    renderSpark(series);
    const g = c.getContext("2d");
    const a = Math.min(start, at(e)) * c.clientWidth, b = Math.max(start, at(e)) * c.clientWidth;
    g.fillStyle = "rgba(37, 99, 235, .18)";
    g.fillRect(a, 0, b - a, c.clientHeight);
  });
  c.addEventListener("pointerup", (e) => {
    if (start === null) return;
    const a = Math.min(start, at(e)), b = Math.max(start, at(e));
    start = null;
    if (b - a < 0.01) { renderSpark(series); return; }
    const from = state.to - state.span;
    setWindow(from + b * state.span, (b - a) * state.span);
  });
}

// --- tables --------------------------------------------------------------------

const badge = (t, cls = "") => `<span class="badge ${cls}">${esc(t)}</span>`;

const tables = {
  devices: {
    cols: ["Device", "Vendor", "Addresses", "Hostnames · services", "Conns", "Lookups", "Up", "Down", "Active"],
    num: [4, 5, 6, 7],
    row: (d) => [
      `${esc(d.label)}<div class="sub mono">${esc(d.mac)}</div>`,
      esc(d.randomized ? "private MAC" : d.vendor_short || d.vendor || "") + (d.role ? " " + badge(d.role) : ""),
      `<span class="mono">${(d.ips || []).map(esc).join("<br>")}</span>`,
      [...(d.hostnames || []), ...(d.services || [])].map((x) => badge(x)).join(""),
      d.flows, d.dns_queries, bytes(d.bytes_out), bytes(d.bytes_in),
      `${clock(d.active_from)}–${clock(d.active_to)}`,
    ],
    id: (d) => d.id,
    sort: (d) => -(d.bytes_in + d.bytes_out),
  },
  flows: {
    cols: ["Opened", "Device", "Remote", "Name", "App", "State", "Up", "Down", "Last"],
    num: [6, 7],
    row: (f) => [
      clock(f.first_seen),
      esc(f.device_name || f.client_ip),
      `<span class="mono">${esc(f.remote_ip)}:${f.remote_port}/${esc(f.proto)}</span>`,
      esc(f.name) + (f.sni && f.qname && f.sni !== f.qname ? `<div class="sub">dns: ${esc(f.qname)}</div>` : ""),
      esc(f.app),
      badge(f.state, f.state) + (f.closed ? badge(f.end_reason || "closed", "closed") : ""),
      bytes(f.bytes_out), bytes(f.bytes_in), clock(f.last_seen),
    ],
    id: (f) => (f.name ? `domain:${f.name}` : `ip:${f.remote_ip}`),
  },
  dns: {
    cols: ["Time", "Device", "Type", "Name", "Result", "ms", "Answers (TTL)"],
    num: [5],
    row: (q) => [
      clock(q.ts), esc(q.device_name || q.client_ip), esc(q.qtype), esc(q.qname),
      q.rcode === "NOERROR" ? esc(q.rcode) : badge(q.rcode, "err"),
      q.latency_ms ? q.latency_ms.toFixed(1) : "",
      `<span class="mono">${(q.answers || []).map((a) => `${esc(a.data)} (${a.ttl}s)`).join("<br>")}</span>`,
    ],
    id: (q) => `domain:${q.qname}`,
  },
  facts: {
    cols: ["Relation", "From", "To", "From time", "Until", "Seen", "Source", "Details"],
    num: [5],
    row: (f) => [
      badge(f.rel), esc(f.src_label || f.src), esc(f.dst_label || f.dst), stamp(f.first_seen), stamp(f.last_seen), f.count, esc(f.source),
      Object.entries(f.attrs || {}).map(([k, v]) => `${esc(k)}=${esc(v)}`).join(" "),
    ],
    id: (f) => f.dst,
  },
  wifi: {
    cols: ["SSID", "BSSID", "Security", "Channel", "Clients", "First seen", "Last seen"],
    num: [3, 4],
    row: (n) => [
      esc(n.ssid) || badge("hidden", "closed"),
      `<span class="mono">${esc(n.bssid)}</span>`,
      n.security ? badge(n.security) : "",
      n.channel || "",
      n.clients ?? 0, stamp(n.first_seen), stamp(n.last_seen),
    ],
    id: (n) => `device:${n.bssid}`,
  },
  sensors: {
    cols: ["Sensor", "Version", "Interfaces", "First seen", "Last seen", "Packets", "Kernel drops", "Events dropped"],
    num: [5, 6, 7],
    row: (s) => [esc(s.name), esc(s.version), esc((s.interfaces || []).join(", ")), stamp(s.first_seen), stamp(s.last_seen),
      s.stats?.packets ?? "", s.stats?.kernel_drops ?? "", s.stats?.events_dropped ?? ""],
    id: () => null,
  },
};

function renderTable(t) {
  const spec = tables[t];
  const rows = [...(state.data[t] || [])];
  if (spec.sort) rows.sort((a, b) => spec.sort(a) - spec.sort(b));
  const el = $(`#t-${t}`);
  const head = `<thead><tr>${spec.cols.map((c, i) => `<th class="${spec.num?.includes(i) ? "num" : ""}">${esc(c)}</th>`).join("")}</tr></thead>`;
  if (!rows.length) {
    el.innerHTML = head + `<tbody><tr><td class="empty" colspan="${spec.cols.length}">Nothing in this window.</td></tr></tbody>`;
    return;
  }
  el.innerHTML = head + "<tbody>" + rows.map((r, i) =>
    `<tr data-i="${i}">${spec.row(r).map((c, j) => `<td class="${spec.num?.includes(j) ? "num" : ""}">${c}</td>`).join("")}</tr>`).join("") + "</tbody>";
  el.querySelector("tbody").onclick = (e) => {
    const tr = e.target.closest("tr[data-i]");
    if (!tr) return;
    const id = spec.id(rows[Number(tr.dataset.i)]);
    if (id) openEntity(id);
  };
}

// --- graph ----------------------------------------------------------------------

let engine = null;
let engineState = "loading";
const diagram = new Diagram($("#diagram"), { onSelect: openEntity });

function theme() {
  const t = document.documentElement.dataset.theme;
  if (t) return t;
  return matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function graphOpts() {
  return { collapse: state.gopts.collapse ? "1" : "0", dns: state.gopts.dns ? "1" : "0", identity: state.gopts.identity ? "1" : "0", top: String(state.gopts.top) };
}

async function renderGraph(seq) {
  const note = $("#graph-note");
  if (engineState === "loading") {
    diagram.message(`Loading the graph engine…<div class="progress"><div id="wasm-progress"></div></div>`);
    await engineReady;
  }
  if (seq !== refreshSeq) return;
  diagram.loading("Loading graph…");
  const query = params(graphOpts()).toString();
  const serverDraw = async () => {
    const [g, svg] = await Promise.all([api("graph", graphOpts()), api("graph", { ...graphOpts(), format: "svg", theme: theme(), layout: state.layout }, true)]);
    return { graph: g, svg, by: `drawn by the server (${state.layout})` };
  };
  let out;
  try {
    if (engineState === "ready" && state.layout === "dagre") {
      out = await track(engine.call("graph", { query, theme: theme(), layout: state.layout }));
      out.by = "drawn in your browser (WASM)";
    } else {
      out = await track(serverDraw());
    }
  } catch (e) {
    if (engineState !== "ready" || state.layout !== "dagre") {
      diagram.message(esc(e.message));
      return;
    }
    console.warn("WASM drawing failed, asking the server:", e);
    try {
      out = await track(serverDraw());
    } catch (e2) {
      diagram.message(esc(e2.message));
      return;
    }
  }
  if (seq !== refreshSeq) return;
  state.graph = out.graph;
  if (!out.graph.nodes?.length) {
    diagram.message("No activity in this window.");
  } else {
    diagram.show(out.svg);
  }
  const g = out.graph;
  note.textContent = `${g.nodes?.length || 0} nodes · ${g.edges?.length || 0} edges` +
    (g.truncated ? ` · showing each device's top ${state.gopts.top} destinations` : "") +
    (g.precision === "hour" ? " · hourly precision" : "") +
    ` · ${out.by}`;
}

const engineReady = new Promise((resolve) => {
  try {
    engine = new Engine({
      onProgress: (loaded, total) => {
        const bar = document.getElementById("wasm-progress");
        if (bar) bar.style.width = total && loaded <= total ? `${(loaded / total) * 100}%` : "60%";
      },
      onReady: (v) => {
        engineState = "ready";
        $("#version").textContent = `netgraph ${v}`;
        engine.call("configure", { base: location.origin, token }).finally(resolve);
      },
      onFailed: (err) => {
        engineState = "failed";
        console.warn("WASM engine unavailable, using server rendering:", err);
        resolve();
      },
    });
  } catch (e) {
    engineState = "failed";
    resolve();
  }
});

function download(name, text, type) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type }));
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

function fileStamp() {
  const d = new Date(state.to);
  return `${d.getFullYear()}${pad2(d.getMonth() + 1)}${pad2(d.getDate())}-${pad2(d.getHours())}${pad2(d.getMinutes())}`;
}

// --- entity panel -------------------------------------------------------------------

async function openEntity(id) {
  const panel = $("#panel");
  panel.hidden = false;
  $("#panel-body").innerHTML = `<p class="muted">Loading ${esc(id)}…</p>`;
  let d;
  try {
    d = await track(api("entity", { id }));
  } catch (e) {
    $("#panel-body").innerHTML = `<h2>${esc(id)}</h2><p class="muted">${esc(e.message)}</p>`;
    return;
  }
  const attrs = Object.entries(d.attrs || {}).map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("");
  const dev = d.device;
  const devInfo = dev ? `
    <dt>addresses</dt><dd class="mono">${(dev.ips || []).map(esc).join(", ")}</dd>
    <dt>hostnames</dt><dd>${(dev.hostnames || []).map(esc).join(", ")}</dd>
    <dt>services</dt><dd>${(dev.services || []).map(esc).join(", ")}</dd>
    <dt>traffic</dt><dd>↑ ${bytes(dev.bytes_out)} ↓ ${bytes(dev.bytes_in)} · ${dev.flows} conns · ${dev.dns_queries} lookups</dd>` : "";
  const link = (eid, label) => `<a data-id="${esc(eid)}">${esc(label || eid)}</a>`;
  const facts = (d.facts || []).map((f) => {
    const out = f.src === d.id;
    return `<li><time>${clock(f.first_seen)}–${clock(f.last_seen)}</time>${badge(f.rel)} ${out ? "→" : "←"} ${out ? link(f.dst, f.dst_label) : link(f.src, f.src_label)} <span class="muted">×${f.count} ${esc(f.source)}</span></li>`;
  }).join("");
  const flows = (d.flows || []).slice(0, 100).map((f) =>
    `<li><time>${clock(f.first_seen)}</time>${esc(f.device_name || f.client_ip)} → ${link(f.name ? "domain:" + f.name : "ip:" + f.remote_ip, f.name || f.remote_ip)}:${f.remote_port}/${esc(f.proto)} ${badge(f.state, f.state)}${f.closed ? badge(f.end_reason, "closed") : ""} <span class="muted">↑${bytes(f.bytes_out)} ↓${bytes(f.bytes_in)}</span></li>`).join("");
  const timeline = (d.timeline || []).slice(-300).map((e) => `<li><time>${clock(e.ts)}</time>${badge(e.type)} ${esc(e.detail)}</li>`).join("");
  $("#panel-body").innerHTML = `
    <h2>${esc(d.label || d.key)}</h2>
    <div class="muted mono">${esc(d.id)}</div>
    <dl><dt>first seen</dt><dd>${stamp(d.first_seen)}</dd><dt>last seen</dt><dd>${stamp(d.last_seen)}</dd>${devInfo}${attrs}</dl>
    ${facts ? `<h3>Relationships in this window</h3><ul>${facts}</ul>` : ""}
    ${flows ? `<h3>Connections</h3><ul>${flows}</ul>` : ""}
    ${timeline ? `<h3>Timeline</h3><ul>${timeline}</ul>` : ""}
    <p><a data-filter="${esc(filterFor(d))}">Filter the window to this ${esc(d.kind)}</a></p>`;
  $("#panel-body").onclick = (e) => {
    const a = e.target.closest("a");
    if (!a) return;
    if (a.dataset.id) openEntity(a.dataset.id);
    if (a.dataset.filter) { state.filter = a.dataset.filter; $("#filter").value = state.filter; refresh(); }
  };
}

function filterFor(d) {
  if (d.kind === "device") return `device:${d.key}`;
  if (d.kind === "ip") return `ip:${d.key}`;
  if (d.kind === "domain") return `domain:${d.key}`;
  return "";
}

// --- live ---------------------------------------------------------------------------

let source = null;
let liveTimer = null;
function setLive(on) {
  state.live = on;
  source?.close();
  source = null;
  clearInterval(liveTimer);
  if (on) {
    let pending = null;
    source = new EventSource(`/api/v1/live?token=${encodeURIComponent(token)}`);
    source.addEventListener("ingest", () => {
      // Batches arrive every couple of seconds; refresh at most that often.
      if (!pending) pending = setTimeout(() => { pending = null; refresh(); }, 2000);
    });
    liveTimer = setInterval(refresh, 30_000);
  }
  refresh();
}

// --- wiring ---------------------------------------------------------------------------

function selectTab(t) {
  state.tab = t;
  for (const b of $$(".tabs button")) b.setAttribute("aria-selected", String(b.dataset.tab === t));
  for (const v of $$(".view")) v.hidden = v.id !== `view-${t}`;
  refresh();
}

function init() {
  const saved = localStorage.getItem("netgraph.theme");
  if (saved) document.documentElement.dataset.theme = saved;
  loadHash();
  $("#filter").value = state.filter;
  $("#g-collapse").checked = state.gopts.collapse;
  $("#g-dns").checked = state.gopts.dns;
  $("#g-identity").checked = state.gopts.identity;
  $("#g-top").value = state.gopts.top;
  $("#g-layout").value = state.layout;

  $("#back").onclick = () => setWindow(state.to - state.span / 2, state.span);
  $("#fwd").onclick = () => setWindow(state.to + state.span / 2, state.span);
  $("#zoomout").onclick = () => setWindow(state.to + state.span / 2, state.span * 2, { live: state.live });
  $("#live").onclick = () => setLive(!state.live);
  for (const b of $$(".presets button")) b.onclick = () => setWindow(Date.now(), parseSpan(b.dataset.span), { live: state.live });
  const fromTo = () => {
    const f = new Date($("#from").value).getTime(), t = new Date($("#to").value).getTime();
    if (f < t) setWindow(t, t - f);
  };
  $("#from").onchange = fromTo;
  $("#to").onchange = fromTo;
  let typing;
  $("#filter").oninput = () => { clearTimeout(typing); typing = setTimeout(() => { state.filter = $("#filter").value; refresh(); }, 400); };
  for (const b of $$(".tabs button")) b.onclick = () => selectTab(b.dataset.tab);
  for (const [id, k] of [["#g-collapse", "collapse"], ["#g-dns", "dns"], ["#g-identity", "identity"]]) {
    $(id).onchange = () => { state.gopts[k] = $(id).checked; refresh(); };
  }
  $("#g-top").onchange = () => { state.gopts.top = Number($("#g-top").value) || 15; refresh(); };
  $("#g-layout").onchange = () => { state.layout = $("#g-layout").value; refresh(); };
  $("#g-fit").onclick = () => diagram.fit();
  $("#g-svg").onclick = () => { const svg = $("#diagram svg"); if (svg) download(`netgraph-${fileStamp()}.svg`, svg.outerHTML, "image/svg+xml"); };
  $("#g-d2").onclick = async () => {
    if (!state.graph) return;
    const script = engineState === "ready"
      ? (await engine.call("d2", { graph: state.graph, theme: theme() })).script
      : await api("graph", { ...graphOpts(), format: "d2" }, true);
    download(`netgraph-${fileStamp()}.d2`, script, "text/plain");
  };
  $("#panel-close").onclick = () => { $("#panel").hidden = true; };
  $("#theme").onclick = () => {
    const next = theme() === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem("netgraph.theme", next); } catch { /* private mode */ }
    refresh();
  };
  document.addEventListener("keydown", (e) => {
    if (e.target.matches("input, select, textarea")) return;
    const k = e.key;
    if (k === "Escape") $("#panel").hidden = true;
    else if (k === "[") $("#back").click();
    else if (k === "]") $("#fwd").click();
    else if (k === "l") $("#live").click();
    else if (k === "/") { e.preventDefault(); $("#filter").focus(); }
    else if (k >= "1" && Number(k) <= $$(".tabs button").length) selectTab($$(".tabs button")[Number(k) - 1].dataset.tab);
  });
  brush();
  addEventListener("resize", () => renderSpark(series));
  // A pasted or edited link changes only the hash: follow it.
  addEventListener("hashchange", () => {
    if (location.hash.slice(1) === lastHash) return;
    const wasLive = state.live;
    loadHash();
    $("#filter").value = state.filter;
    if (state.live !== wasLive) setLive(state.live); else selectTab(state.tab);
  });
  selectTab(state.tab);
  if (state.live) setLive(true);
}

init();
