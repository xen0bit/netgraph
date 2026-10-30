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
  gopts: { collapse: true, dns: true, sites: true, anomalies: true, networks: true, identity: false, top: 15 },
  // dagre runs inside the WASM engine; d2's ELK needs a host-provided
  // synchronous ELK in the browser, so "elk" is drawn by the server.
  layout: "dagre",
  graph: null,
  data: {},
  // Per table: the column it is sorted by ({col, dir}), and how many rows
  // to ask for when "load more" raised the API's default.
  sort: {},
  limits: {},
  // The entity whose details are open, so a link can reopen them.
  open: "",
};

function loadHash() {
  const p = new URLSearchParams(location.hash.slice(1));
  if (p.get("to")) state.to = Number(p.get("to"));
  if (p.get("span")) state.span = Number(p.get("span"));
  if (p.get("from") && p.get("to")) state.span = state.to - Number(p.get("from"));
  state.live = p.get("live") === "1" || !p.has("to");
  state.filter = p.get("q") || "";
  if (p.get("tab")) state.tab = p.get("tab");
  for (const k of ["collapse", "dns", "sites", "anomalies", "networks", "identity"]) if (p.has(k)) state.gopts[k] = p.get(k) === "1";
  if (p.has("top")) state.gopts.top = Number(p.get("top"));
  // sort=<table>.<column>.<asc|desc>
  state.sort = {};
  const [st, col, dir] = (p.get("sort") || "").split(".");
  if (tables[st] && tables[st].keys[Number(col)] && (dir === "asc" || dir === "desc")) state.sort[st] = { col: Number(col), dir };
  state.open = p.get("open") || "";
}

function saveHash() {
  const p = new URLSearchParams();
  if (state.live) { p.set("live", "1"); p.set("span", state.span); } else { p.set("from", state.to - state.span); p.set("to", state.to); }
  if (state.filter) p.set("q", state.filter);
  if (state.tab !== "graph") p.set("tab", state.tab);
  for (const k of ["collapse", "dns", "sites", "anomalies", "networks", "identity"]) p.set(k, state.gopts[k] ? "1" : "0");
  p.set("top", state.gopts.top);
  const so = state.sort[state.tab];
  if (so) p.set("sort", `${state.tab}.${so.col}.${so.dir}`);
  if (state.open) p.set("open", state.open);
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
    if (["device", "ip", "domain", "port", "proto", "app", "dir", "asn", "cc", "multicast"].includes(k)) out[k] = v;
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
  let retried = false;
  for (;;) {
    const headers = token ? { Authorization: `Bearer ${token}` } : {};
    const resp = await fetch(`/api/v1/${path}?${params(extra)}`, { headers });
    if (resp.status === 401) {
      if (retried) throw new Error(`${path}: read token required`);
      retried = true;
      if (!await askToken()) throw new Error(`${path}: read token required`);
      continue;
    }
    if (!resp.ok) {
      let msg = resp.statusText;
      try { msg = (await resp.json()).error || msg; } catch { /* not JSON */ }
      throw new Error(`${path}: ${msg}`);
    }
    return raw ? resp.text() : resp.json();
  }
}

// send writes JSON (a JSON body makes a cross-site request need a CORS
// preflight, which the server never grants).
async function send(method, path, body) {
  let retried = false;
  for (;;) {
    const headers = { "Content-Type": "application/json" };
    if (token) headers.Authorization = `Bearer ${token}`;
    const resp = await fetch(`/api/v1/${path}`, { method, headers, body: JSON.stringify(body) });
    if (resp.status === 401) {
      if (retried) throw new Error("read token required");
      retried = true;
      if (!await askToken()) throw new Error("read token required");
      continue;
    }
    if (!resp.ok) {
      let msg = resp.statusText;
      try { msg = (await resp.json()).error || msg; } catch { /* not JSON */ }
      throw new Error(msg);
    }
    return;
  }
}

// askToken shares one dialog across the parallel requests refresh() starts.
// Without this, three 401s call showModal() on an already-open dialog.
let tokenPrompt = null;
function askToken() {
  if (tokenPrompt) return tokenPrompt;
  const dlg = $("#token-dialog");
  const input = $("#token-input");
  tokenPrompt = new Promise((resolve) => {
    const done = () => {
      dlg.removeEventListener("close", done);
      const cancel = dlg.returnValue === "cancel";
      const v = input.value.trim();
      if (!cancel && v) {
        token = v;
        try { localStorage.setItem("netgraph.token", token); } catch { /* private mode */ }
        engine?.call("configure", { base: location.origin, token }).catch(() => {});
        if (state.live) openLive();
      }
      tokenPrompt = null;
      resolve(cancel ? "" : token);
    };
    dlg.addEventListener("close", done);
    input.value = "";
    dlg.returnValue = "";
    if (!dlg.open) dlg.showModal();
  });
  return tokenPrompt;
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
  const [summary, series, anomalies] = await Promise.all([
    track(api("summary")).catch(() => null),
    track(api("timeseries", { step })).catch(() => null),
    track(api("anomalies")).catch(() => null),
  ]);
  if (seq !== refreshSeq) return;
  renderSummary(summary, anomalies);
  renderSpark(series);
  await renderTab(seq);
}

const tablePath = { devices: "devices", flows: "flows", dns: "dns", facts: "facts", wifi: "wifi", sensors: "sensors", anomalies: "anomalies" };

async function renderTab(seq) {
  const t = state.tab;
  try {
    if (t === "graph") return await renderGraph(seq);
    const path = tablePath[t];
    let rows = await track(api(path, state.limits[t] ? { limit: state.limits[t] } : {}));
    if (seq !== refreshSeq) return;
    if (t === "anomalies") {
      $("#anomaly-note").textContent = rows?.learning
        ? "Learning the network: until it has a day of history, only the checks that need none run (beacons, failed lookups, DNS tunnels, access points, scans, password guessing). New devices, new destinations, upload spikes, new services and inbound surges follow."
        : "";
      rows = rows?.anomalies;
    }
    state.data[t] = rows || [];
    renderTable(t);
  } catch { /* status shows it */ }
}

function renderSummary(s, rep) {
  const el = $("#summary");
  if (!s) { el.textContent = ""; return; }
  const as = rep?.anomalies || [];
  const top = ["high", "medium", "low"].find((sev) => as.some((a) => a.severity === sev));
  el.innerHTML = [
    as.length ? `<a class="badge sev-${top}" data-tab="anomalies" title="Most severe: ${esc(top)}">${as.length} ${as.length === 1 ? "anomaly" : "anomalies"}</a>`
      : rep?.learning ? `<span class="hour" title="Checks that compare with history start a day after the first sensor reported">learning the network</span>` : "",
    `<span><b>${s.devices}</b> devices</span>`,
    `<span title="Connections in the window; inbound ones were opened from outside to a device here"><b>${s.flows}</b> connections${s.inbound ? ` (<b>${s.inbound}</b> inbound)` : ""}, peak <b>${s.peak_connections}</b> open</span>`,
    `<span><b>${s.dns_queries}</b> lookups of <b>${s.domains}</b> names</span>`,
    `<span title="Bytes sent and received by the devices here">sent <b>${bytes(s.bytes_out)}</b> · received <b>${bytes(s.bytes_in)}</b></span>`,
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

// A connection's direction, from the local network's point of view.
const dirs = {
  out: ["out", "A device here connected out"],
  in: ["in", "Opened from outside to a device here"],
  local: ["lan", "Both ends are here"],
  external: ["transit", "Neither end is here"],
};
const dirBadge = (d) => `<span class="badge dir-${esc(d)}" title="${esc(dirs[d]?.[1] || d)}">${esc(dirs[d]?.[0] || d)}</span>`;

// hostPort is an address and port as they are written: [v6]:port.
const hostPort = (ip, port) => (String(ip).includes(":") ? `[${ip}]` : ip) + (port ? `:${port}` : "");

// ends is a connection's client and server as HTML: the device by name, the
// other end by address, the server with its port (as model.Flow.Ends).
function ends(f) {
  const dev = `<b>${esc(f.device_name || (f.direction === "in" ? f.server_ip : f.client_ip))}</b>`;
  if (f.direction === "in") {
    return [`<span class="mono">${esc(hostPort(f.client_ip, f.client_port))}</span>${network(f)}`, `${dev}<span class="mono">:${f.server_port}/${esc(f.proto)}</span>`];
  }
  if (f.peer_name) return [dev, `<b>${esc(f.peer_name)}</b><span class="mono">:${f.server_port}/${esc(f.proto)}</span>`];
  return [dev, `<span class="mono">${esc(hostPort(f.server_ip, f.server_port))}/${esc(f.proto)}</span>${network(f)}`];
}

// network is the remote end's AS and country, under its address.
const network = (f) => f.asn
  ? `<div class="sub" title="${esc(`AS${f.asn} ${f.as_org || ""}`)}">${esc(asName(f.asn, f.as_org))}${f.country ? ` · ${esc(f.country)}` : ""}</div>`
  : "";
const asName = (n, org) => `AS${n}${org ? " " + org : ""}`;

// peerID is the entity a connection's row opens: what the device talked to,
// or the client that reached it.
const peerID = (f) => f.peer_device || (f.direction !== "in" && f.name ? `domain:${f.name}` : `ip:${f.remote_ip}`);

const tables = {
  devices: {
    cols: ["Device", "Vendor", "Addresses", "Hostnames · services", "Conns", "Lookups", "Sent", "Received", "Active"],
    titles: { 4: "Connections; how many of them came in from outside", 6: "Bytes the device sent", 7: "Bytes the device received" },
    num: [4, 5, 6, 7],
    row: (d) => [
      `${esc(d.label)}${d.user_label && d.auto_label ? `<div class="sub">${esc(d.auto_label)}</div>` : ""}<div class="sub mono">${esc(d.mac)}</div>`,
      esc(d.randomized ? "private MAC" : d.vendor_short || d.vendor || "") + (d.role ? " " + badge(d.role) : ""),
      `<span class="mono">${(d.ips || []).map(esc).join("<br>")}</span>`,
      (d.serves?.length ? `<span class="badge dir-in" title="Ports clients connected to">serves ${esc(d.serves.join(", "))}</span>` : "") +
        [...(d.hostnames || []), ...(d.services || [])].map((x) => badge(x)).join(""),
      d.flows + (d.inbound ? `<div class="sub">${d.inbound} in</div>` : ""), d.dns_queries, bytes(d.bytes_out), bytes(d.bytes_in),
      `${clock(d.active_from)}–${clock(d.active_to)}`,
    ],
    keys: [(d) => d.label, (d) => (d.randomized ? "private MAC" : d.vendor_short || d.vendor), (d) => addrKey(d.ips?.[0]),
      (d) => [...(d.hostnames || []), ...(d.services || [])].join(" "), (d) => d.flows, (d) => d.dns_queries, (d) => d.bytes_out,
      (d) => d.bytes_in, (d) => d.active_from],
    id: (d) => d.id,
    sort: (d) => -(d.bytes_in + d.bytes_out),
  },
  flows: {
    cols: ["Opened", "Dir", "Client", "", "Server", "Name", "App", "State", "Sent", "Received", "Last"],
    titles: {
      1: "out: a device here connected out · in: opened from outside · lan: both ends here",
      2: "The end that opened the connection", 4: "The end that accepted it, with its port",
      5: "What the client asked for (TLS SNI, HTTP Host) or the DNS name it looked up",
      8: "Bytes the device sent", 9: "Bytes the device received",
    },
    num: [8, 9],
    row: (f) => {
      const [client, server] = ends(f);
      return [
        clock(f.first_seen),
        dirBadge(f.direction),
        client, `<span class="muted">→</span>`, server,
        esc(f.name) + (f.sni && f.qname && f.sni !== f.qname ? `<div class="sub">dns: ${esc(f.qname)}</div>` : ""),
        esc(f.app),
        badge(f.state, f.state) + (f.closed ? badge(f.end_reason || "closed", "closed") : ""),
        bytes(f.bytes_out), bytes(f.bytes_in), clock(f.last_seen),
      ];
    },
    keys: [(f) => f.first_seen, (f) => f.direction,
      (f) => (f.direction === "in" ? addrKey(f.client_ip) : f.device_name || addrKey(f.client_ip)), null,
      (f) => (f.direction === "in" ? f.device_name || addrKey(f.server_ip) : f.peer_name || addrKey(f.server_ip)),
      (f) => f.name, (f) => f.app, (f) => f.state, (f) => f.bytes_out, (f) => f.bytes_in, (f) => f.last_seen],
    id: peerID,
  },
  dns: {
    cols: ["Time", "Device", "Type", "Name", "Result", "ms", "Answers (TTL)"],
    num: [5],
    row: (q) => [
      clock(q.ts), esc(q.device_name || q.client_ip), esc(q.qtype),
      esc(q.qname) + (q.count > 1 ? ` <span class="muted">×${q.count}</span>` : ""),
      q.rcode === "NOERROR" ? esc(q.rcode) : badge(q.rcode, "err"),
      q.latency_ms ? q.latency_ms.toFixed(1) : "",
      `<span class="mono">${(q.answers || []).map((a) => `${esc(a.data)} (${a.ttl}s)`).join("<br>")}</span>`,
    ],
    keys: [(q) => q.ts, (q) => q.device_name || addrKey(q.client_ip), (q) => q.qtype, (q) => q.qname, (q) => q.rcode,
      (q) => q.latency_ms, (q) => q.answers?.length || 0],
    id: (q) => `domain:${q.qname}`,
  },
  facts: {
    cols: ["Relation", "From", "To", "From time", "Until", "Seen", "Source", "Details"],
    num: [5],
    row: (f) => [
      badge(f.rel), esc(f.src_label || f.src), esc(f.dst_label || f.dst), stamp(f.first_seen), stamp(f.last_seen), f.count, esc(f.source),
      Object.entries(f.attrs || {}).map(([k, v]) => `${esc(k)}=${esc(v)}`).join(" "),
    ],
    keys: [(f) => f.rel, (f) => f.src_label || f.src, (f) => f.dst_label || f.dst, (f) => f.first_seen, (f) => f.last_seen,
      (f) => f.count, (f) => f.source, null],
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
    keys: [(n) => n.ssid, (n) => n.bssid, (n) => n.security, (n) => n.channel, (n) => n.clients, (n) => n.first_seen, (n) => n.last_seen],
    id: (n) => `device:${n.bssid}`,
  },
  anomalies: {
    cols: ["Severity", "When", "Kind", "Device", "What"],
    titles: { 4: "Click a row to see it on the graph" },
    row: (a) => [badge(a.severity, `sev-${a.severity}`), stamp(a.ts), esc(a.kind.replaceAll("_", " ")), esc(a.device_name || ""), esc(a.summary)],
    keys: [(a) => ({ high: 3, medium: 2, low: 1 })[a.severity] || 0, (a) => a.ts, (a) => a.kind, (a) => a.device_name, (a) => a.summary],
    id: (a) => a.device || a.entity || null,
    // On the graph, narrowed to what it is about: the address or network
    // it names (the device's connections with it), else the device. The
    // details start with the anomaly, whatever its severity.
    open: (a) => {
      const id = a.device || a.entity;
      // Their entity IDs read as filters: ip:…, asn:…, device:….
      const narrow = [a.entity, a.device].find((x) => /^(ip|asn|device):/.test(x || ""));
      if (narrow) { state.filter = narrow; $("#filter").value = narrow; }
      selectTab("graph").then(() => openEntity(id, { anomaly: a }));
    },
  },
  sensors: {
    cols: ["Sensor", "Version", "Interfaces", "First seen", "Last seen", "Packets", "Kernel drops", "Events dropped"],
    num: [5, 6, 7],
    row: (s) => [esc(s.name), esc(s.version), esc((s.interfaces || []).join(", ")), stamp(s.first_seen), stamp(s.last_seen),
      s.stats?.packets ?? "", s.stats?.kernel_drops ?? "", s.stats?.events_dropped ?? ""],
    keys: [(s) => s.name, (s) => s.version, (s) => (s.interfaces || []).join(" "), (s) => s.first_seen, (s) => s.last_seen,
      (s) => s.stats?.packets, (s) => s.stats?.kernel_drops, (s) => s.stats?.events_dropped],
    id: () => null,
  },
};

// What the API returns at most by default, and at most at all: past the
// default, "load more" doubles the request.
const limits = { flows: [1000, 100000], dns: [500, 50000], facts: [2000, 100000] };

// addrKey sorts addresses by their numbers: 10.0.0.9 before 10.0.0.10.
const addrKey = (ip) => {
  if (!ip) return "";
  const v4 = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip);
  if (v4) return "4" + v4.slice(1).map((o) => o.padStart(3, "0")).join(".");
  return "6" + String(ip).toLowerCase();
};

// compare orders two sort keys: numbers by value, text naturally
// ("host2" before "host10"), and empty values last whichever the direction.
const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: "base" });
function compare(a, b, dir) {
  const ea = a === null || a === undefined || a === "", eb = b === null || b === undefined || b === "";
  if (ea || eb) return ea === eb ? 0 : ea ? 1 : -1;
  const c = typeof a === "number" && typeof b === "number" ? a - b : collator.compare(String(a), String(b));
  return dir === "desc" ? -c : c;
}

// A column's first click sorts numbers largest first and text A to Z; the
// second reverses it; the third goes back to the table's own order.
function sortBy(t, col) {
  const spec = tables[t];
  const cur = state.sort[t];
  const sample = state.data[t]?.map(spec.keys[col]).find((v) => v !== null && v !== undefined && v !== "");
  const first = typeof sample === "number" ? "desc" : "asc";
  if (!cur || cur.col !== col) state.sort[t] = { col, dir: first };
  else if (cur.dir === first) state.sort[t] = { col, dir: first === "asc" ? "desc" : "asc" };
  else delete state.sort[t];
  saveHash();
  renderTable(t);
}

// --- CSV ------------------------------------------------------------------------

// Fields holding unix milliseconds, written as times.
const timeFields = new Set(["ts", "first_seen", "last_seen", "active_from", "active_to", "expires"]);

// csvCell quotes a value for CSV. Text from the network could be a
// spreadsheet formula ("=HYPERLINK(...)" as a hostname), so text starting
// like one is prefixed with a quote.
function csvCell(k, v) {
  if (v === null || v === undefined) return "";
  if (timeFields.has(k) && typeof v === "number" && v > 0) v = new Date(v).toISOString();
  else if (Array.isArray(v)) v = v.map((x) => (typeof x === "object" ? JSON.stringify(x) : x)).join("; ");
  else if (typeof v === "object") v = JSON.stringify(v);
  let s = String(v);
  if (typeof v !== "number" && typeof v !== "boolean" && /^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return /[",\r\n]/.test(s) ? `"${s.replaceAll('"', '""')}"` : s;
}

// toCSV writes rows as the API returned them, every field, in the order
// the table shows them.
function toCSV(rows) {
  const cols = [];
  for (const r of rows) for (const k of Object.keys(r)) if (!cols.includes(k)) cols.push(k);
  return [cols.join(","), ...rows.map((r) => cols.map((k) => csvCell(k, r[k])).join(","))].join("\r\n") + "\r\n";
}

async function loadMore(t) {
  const [def, max] = limits[t] || [];
  const asked = state.limits[t] || def;
  if (!def || asked >= max) return;
  const next = Math.min(asked * 2, max);
  const offset = (state.data[t] || []).length;
  try {
    const add = await track(api(tablePath[t], { limit: next - asked, offset }));
    if (!Array.isArray(add) || add.length === 0) return;
    state.limits[t] = next;
    state.data[t] = [...(state.data[t] || []), ...add];
    renderTable(t);
  } catch { /* status shows it */ }
}

function exportAll(t) {
  if (!tablePath[t] || t === "sensors") return;
  return track(api("export", { kind: t }, true)).then((text) => {
    download(`netgraph-${t}-${fileStamp()}.csv`, text, "text/csv");
  }).catch(() => {});
}

function renderTable(t) {
  const spec = tables[t];
  const all = state.data[t] || [];
  const rows = [...all];
  if (spec.sort) rows.sort((a, b) => spec.sort(a) - spec.sort(b));
  const so = state.sort[t];
  if (so) rows.sort((a, b) => compare(spec.keys[so.col](a), spec.keys[so.col](b), so.dir));
  const el = $(`#t-${t}`);
  const tools = tableTools(t, el);
  const head = `<thead><tr>${spec.cols.map((c, i) => {
    const sorted = so?.col === i ? (so.dir === "asc" ? "ascending" : "descending") : "";
    const label = esc(c) + (sorted ? (so.dir === "asc" ? " ▲" : " ▼") : "");
    const cls = spec.num?.includes(i) ? "num" : "";
    const title = spec.titles?.[i] ? ` title="${esc(spec.titles[i])}"` : "";
    return spec.keys[i] && c
      ? `<th class="${cls}"${title}${sorted ? ` aria-sort="${sorted}"` : ""}><button class="sort" data-col="${i}">${label}</button></th>`
      : `<th class="${cls}"${title}>${esc(c)}</th>`;
  }).join("")}</tr></thead>`;
  // Past the API's limit the table is the first rows only: say so, and
  // offer more.
  const [def, max] = limits[t] || [];
  const asked = state.limits[t] || def;
  const capped = def && all.length >= asked;
  tools.querySelector(".count").textContent = `${all.length} ${all.length === 1 ? "row" : "rows"}` +
    (capped ? ` · the first ${asked}${so ? "; sorting covers these only" : ""}` : "");
  const more = tools.querySelector("[data-more]");
  more.hidden = !capped || asked >= max;
  more.onclick = () => loadMore(t);
  tools.querySelector("[data-csv]").disabled = !rows.length;
  tools.querySelector("[data-csv]").onclick = () => download(`netgraph-${t}-${fileStamp()}.csv`, toCSV(rows), "text/csv");
  const exportBtn = tools.querySelector("[data-export]");
  exportBtn.hidden = !tablePath[t] || t === "sensors";
  exportBtn.onclick = () => exportAll(t);
  el.onclick = (e) => {
    const b = e.target.closest("thead button.sort");
    if (b) sortBy(t, Number(b.dataset.col));
  };
  if (!rows.length) {
    el.innerHTML = head + `<tbody><tr><td class="empty" colspan="${spec.cols.length}">Nothing in this window.</td></tr></tbody>`;
    return;
  }
  el.innerHTML = head + "<tbody>" + rows.map((r, i) =>
    `<tr data-i="${i}">${spec.row(r).map((c, j) => `<td class="${spec.num?.includes(j) ? "num" : ""}">${c}</td>`).join("")}</tr>`).join("") + "</tbody>";
  el.querySelector("tbody").onclick = (e) => {
    const tr = e.target.closest("tr[data-i]");
    if (!tr) return;
    const r = rows[Number(tr.dataset.i)];
    const id = spec.id(r);
    if (!id) return;
    if (spec.open) spec.open(r);
    else openEntity(id);
  };
}

// tableTools is the bar above a table: its row count, "load more" and CSV.
function tableTools(t, table) {
  let tools = document.getElementById(`tt-${t}`);
  if (!tools) {
    tools = document.createElement("div");
    tools.id = `tt-${t}`;
    tools.className = "table-tools";
    tools.innerHTML = `<span class="count"></span><button data-more hidden>Load more</button><span class="spacer"></span>
      <button data-export title="Download every row in this window, every field, as CSV">All CSV</button>
      <button data-csv title="Download these rows, every field, as CSV">CSV</button>`;
    table.before(tools);
  }
  return tools;
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
  const b = (k) => (state.gopts[k] ? "1" : "0");
  return { collapse: b("collapse"), dns: b("dns"), sites: b("sites"), anomalies: b("anomalies"), networks: b("networks"), identity: b("identity"), top: String(state.gopts.top) };
}

let lastView = null;
async function renderGraph(seq) {
  const note = $("#graph-note");
  if (engineState === "loading") {
    diagram.message(`Loading the graph engine…<div class="progress"><div id="wasm-progress"></div></div>`);
    await engineReady;
  }
  if (seq !== refreshSeq) return;
  diagram.loading("Loading graph…");
  const query = params(graphOpts()).toString();
  // What is being graphed, apart from Live moving the window forward: a
  // redraw of the same view keeps the person's pan and zoom.
  const view = JSON.stringify([graphOpts(), state.filter, state.layout, state.live ? state.span : [state.to, state.span]]);
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
    diagram.show(out.svg, { keepView: view === lastView });
  }
  lastView = view;
  const g = out.graph;
  note.textContent = `${g.nodes?.length || 0} nodes · ${g.edges?.length || 0} edges` +
    (g.truncated ? ` · showing each device's top ${state.gopts.top} destinations and clients` : "") +
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

async function openEntity(id, { anomaly } = {}) {
  if (!id) return;
  const panel = $("#panel");
  panel.hidden = false;
  state.open = id;
  saveHash();
  if (id.startsWith("other:")) return openRest(id);
  if (id.startsWith("dests:")) id = id.slice("dests:".length);
  if (id.startsWith("clients:")) id = id.slice("clients:".length);
  $("#panel-body").innerHTML = `<p class="muted">Loading ${esc(id)}…</p>`;
  let d;
  try {
    d = await track(api("entity", { id }));
  } catch (e) {
    $("#panel-body").innerHTML = `<h2>${esc(id)}</h2><p class="muted">${esc(e.message)}</p>`;
    return;
  }
  const userLabel = d.attrs?.user_label || "";
  const autoLabel = d.attrs?.auto_label || "";
  const attrs = Object.entries(d.attrs || {}).filter(([k]) => k !== "user_label" && k !== "auto_label")
    .map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("");
  const rename = d.kind === "device" ? `
    <form class="rename" autocomplete="off">
      <input name="label" maxlength="64" aria-label="Device name" value="${esc(userLabel)}" placeholder="${esc(userLabel ? autoLabel : d.label || "Name this device")}">
      <button type="submit">Rename</button>
      ${userLabel ? `<button type="button" data-clear>Use “${esc(autoLabel || d.key)}”</button>` : ""}
      <output class="muted"></output>
    </form>` : "";
  const dev = d.device;
  const devInfo = dev ? `
    <dt>addresses</dt><dd class="mono">${(dev.ips || []).map(esc).join(", ")}</dd>
    <dt>hostnames</dt><dd>${(dev.hostnames || []).map(esc).join(", ")}</dd>
    <dt>services</dt><dd>${(dev.services || []).map(esc).join(", ")}</dd>
    ${dev.serves?.length ? `<dt>serves</dt><dd class="mono">${esc(dev.serves.join(", "))}</dd>` : ""}
    <dt>traffic</dt><dd>sent ${bytes(dev.bytes_out)} · received ${bytes(dev.bytes_in)} · ${dev.flows} conns${dev.inbound ? ` (${dev.inbound} from outside)` : ""} · ${dev.dns_queries} lookups</dd>` : "";
  const link = (eid, label) => `<a data-id="${esc(eid)}">${esc(label || eid)}</a>`;
  const facts = (d.facts || []).map((f) => {
    const out = f.src === d.id;
    return `<li><time>${clock(f.first_seen)}–${clock(f.last_seen)}</time>${badge(f.rel)} ${out ? "→" : "←"} ${out ? link(f.dst, f.dst_label) : link(f.src, f.src_label)} <span class="muted">×${f.count} ${esc(f.source)}</span></li>`;
  }).join("");
  // Each connection as client → server; the peer (what the device talked
  // to, or the client that reached it) links to its details.
  const flows = (d.flows || []).slice(0, 100).map((f) => {
    const dev = esc(f.device_name || (f.direction === "in" ? f.server_ip : f.client_ip));
    const line = f.direction === "in"
      ? `${link(peerID(f), hostPort(f.client_ip, f.client_port))} → ${dev}:${f.server_port}/${esc(f.proto)}${f.name ? ` <span class="muted">for ${esc(f.name)}</span>` : ""}`
      : `${dev} → ${link(peerID(f), f.name || f.server_ip)}:${f.server_port}/${esc(f.proto)}`;
    return `<li><time>${clock(f.first_seen)}</time>${dirBadge(f.direction)} ${line} ${badge(f.state, f.state)}${f.closed ? badge(f.end_reason, "closed") : ""} <span class="muted">sent ${bytes(f.bytes_out)} · received ${bytes(f.bytes_in)}</span></li>`;
  }).join("");
  const timeline = (d.timeline || []).slice(-300).map((e) => `<li><time>${clock(e.ts)}</time>${badge(e.type)} ${esc(e.detail)}</li>`).join("");
  const flagged = anomaly
    ? [anomaly.summary, ...Object.entries(anomaly.evidence || {}).map(([k, v]) => `${k}: ${v}`)]
    : state.graph?.nodes?.find((n) => n.id === id)?.attrs?.anomalies?.split("\n");
  const anomalyBox = flagged ? `<div class="anomaly-box"><b>${anomaly ? `${esc(anomaly.severity)} ${esc(anomaly.kind.replaceAll("_", " "))}` : "Anomalies"}</b><ul>${flagged.map((l) => `<li>${esc(l)}</li>`).join("")}</ul></div>` : "";
  $("#panel-body").innerHTML = `${anomalyBox}
    <h2>${esc(d.label || d.key)}</h2>
    <div class="muted mono">${esc(d.id)}</div>${rename}
    <dl><dt>first seen</dt><dd>${stamp(d.first_seen)}</dd><dt>last seen</dt><dd>${stamp(d.last_seen)}</dd>${devInfo}${attrs}</dl>
    ${facts ? `<h3>Relationships in this window</h3><ul>${facts}</ul>` : ""}
    ${flows ? `<h3>Connections</h3><ul>${flows}</ul>` : ""}
    ${timeline ? `<h3>Timeline</h3><ul>${timeline}</ul>` : ""}
    <p><a data-filter="${esc(filterFor(d))}">Filter the window to this ${esc(d.kind)}</a></p>`;
  const form = $("#panel-body form.rename");
  if (form) {
    const save = async (label) => {
      form.querySelector("output").textContent = "Saving…";
      try {
        await send("PUT", `devices/${encodeURIComponent(d.key)}/label`, { label });
      } catch (err) {
        form.querySelector("output").textContent = err.message;
        return;
      }
      openEntity(id);
      refresh();
    };
    form.onsubmit = (e) => { e.preventDefault(); save(form.label.value.trim()); };
    form.querySelector("[data-clear]")?.addEventListener("click", () => save(""));
  }
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
  if (d.kind === "domain" || d.kind === "site") return `domain:${d.key}`;
  if (d.kind === "asn") return `asn:${d.key}`;
  return "";
}

// openRest explains a graph's "N more destinations" (or "N more clients")
// node: what Top N left out for one device, and the ways to see it.
function openRest(id) {
  const n = state.graph?.nodes?.find((x) => x.id === id);
  const clients = id.startsWith("other:clients:");
  const dev = n?.attrs?.device || id.slice(clients ? "other:clients:".length : "other:".length);
  const name = state.graph?.nodes?.find((x) => x.id === dev)?.label || dev;
  const what = clients ? "clients" : "destinations";
  const devFilter = dev.startsWith("device:") ? dev : "ip:" + dev.slice(3);
  // Edges point client → server, so "up" is what the clients sent.
  const traffic = clients
    ? `they sent ${bytes(n?.bytes_out || 0)} and received ${bytes(n?.bytes_in || 0)}`
    : `the device sent ${bytes(n?.bytes_out || 0)} and received ${bytes(n?.bytes_in || 0)}`;
  $("#panel-body").innerHTML = `
    <h2>${esc(n?.label || "More " + what)}</h2>
    <div class="muted">${clients ? "connecting to" : "of"} ${esc(name)}</div>
    <p>Top ${esc(state.gopts.top)} draws each device's busiest ${what}; these ${esc(n?.attrs?.[what] || "")} are left out: ${traffic}.</p>
    <p><a data-id="${esc(dev)}">Details of ${esc(name)}</a></p>
    <p><a data-filter="${esc(devFilter + (clients ? " dir:in" : " dir:out"))}">Filter the window to these ${what}</a>, or raise Top N.</p>`;
  $("#panel-body").onclick = (e) => {
    const a = e.target.closest("a");
    if (!a) return;
    if (a.dataset.id) openEntity(a.dataset.id);
    if (a.dataset.filter) { state.filter = a.dataset.filter; $("#filter").value = state.filter; refresh(); }
  };
}

// --- live ---------------------------------------------------------------------------

let source = null;
let liveTimer = null;
let pending = null;
function openLive() {
  source?.close();
  source = new EventSource(`/api/v1/live?token=${encodeURIComponent(token)}`);
  source.addEventListener("ingest", () => {
    // Batches arrive every couple of seconds; refresh at most that often.
    if (!pending) pending = setTimeout(() => { pending = null; refresh(); }, 2000);
  });
}
function setLive(on) {
  state.live = on;
  source?.close();
  source = null;
  clearInterval(liveTimer);
  clearTimeout(pending);
  pending = null;
  if (!on) {
    // The window stays where Live left it: nothing to fetch again.
    saveHash();
    renderWindow();
    return;
  }
  openLive();
  liveTimer = setInterval(refresh, 30_000);
  refresh();
}

// --- wiring ---------------------------------------------------------------------------

function selectTab(t) {
  state.tab = t;
  for (const b of $$(".tabs button")) b.setAttribute("aria-selected", String(b.dataset.tab === t));
  for (const v of $$(".view")) v.hidden = v.id !== `view-${t}`;
  return refresh();
}

// closePanel hides the details, and forgets them for links.
function closePanel() {
  $("#panel").hidden = true;
  state.open = "";
  saveHash();
}

// --- search ---------------------------------------------------------------------

// The header's search box: devices, addresses, names and networks by key or
// name, from GET /api/v1/search. Enter or a click opens the details.
function search() {
  const input = $("#search"), list = $("#search-results");
  let seq = 0, timer, results = [], active = -1;
  const close = () => { list.hidden = true; input.setAttribute("aria-expanded", "false"); active = -1; };
  const show = () => {
    list.innerHTML = results.length
      ? results.map((r, i) => `<li role="option" id="sr-${i}" data-i="${i}"${i === active ? ` class="active" aria-selected="true"` : ""}>${badge(r.kind)} ${esc(r.label)}${r.label !== r.key ? ` <span class="muted mono">${esc(r.key)}</span>` : ""}</li>`).join("")
      : `<li class="muted">Nothing matches.</li>`;
    list.hidden = false;
    input.setAttribute("aria-expanded", "true");
    if (active >= 0) input.setAttribute("aria-activedescendant", `sr-${active}`);
    else input.removeAttribute("aria-activedescendant");
  };
  const pick = (i) => {
    const r = results[i];
    if (!r) return;
    close();
    input.value = "";
    // Out of the box, so Escape closes the details it opened.
    input.blur();
    openEntity(r.id);
  };
  input.oninput = () => {
    clearTimeout(timer);
    const q = input.value.trim();
    if (q.length < 2) { close(); return; }
    timer = setTimeout(async () => {
      const n = ++seq;
      let rs;
      try { rs = await api("search", { q, limit: 12 }); } catch { return; }
      if (n !== seq) return;
      results = rs || [];
      active = results.length ? 0 : -1;
      show();
    }, 200);
  };
  input.onkeydown = (e) => {
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      if (!results.length) return;
      e.preventDefault();
      active = (active + (e.key === "ArrowDown" ? 1 : -1) + results.length) % results.length;
      show();
    } else if (e.key === "Enter") {
      e.preventDefault();
      pick(Math.max(active, 0));
    } else if (e.key === "Escape") {
      close();
      input.blur();
    }
  };
  // mousedown, not click: it lands before the input's blur closes the list.
  list.onmousedown = (e) => { const li = e.target.closest("li[data-i]"); if (li) { e.preventDefault(); pick(Number(li.dataset.i)); } };
  input.onblur = () => setTimeout(close, 100);
}

function init() {
  const saved = localStorage.getItem("netgraph.theme");
  if (saved) document.documentElement.dataset.theme = saved;
  loadHash();
  $("#filter").value = state.filter;
  $("#g-collapse").checked = state.gopts.collapse;
  $("#g-dns").checked = state.gopts.dns;
  $("#g-sites").checked = state.gopts.sites;
  $("#g-anomalies").checked = state.gopts.anomalies;
  $("#g-networks").checked = state.gopts.networks;
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
  $("#summary").onclick = (e) => { const a = e.target.closest("[data-tab]"); if (a) selectTab(a.dataset.tab); };
  for (const [id, k] of [["#g-collapse", "collapse"], ["#g-dns", "dns"], ["#g-sites", "sites"], ["#g-anomalies", "anomalies"], ["#g-networks", "networks"], ["#g-identity", "identity"]]) {
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
  $("#panel-close").onclick = closePanel;
  $("#theme").onclick = () => {
    const next = theme() === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem("netgraph.theme", next); } catch { /* private mode */ }
    refresh();
  };
  document.addEventListener("keydown", (e) => {
    if (e.target.matches("input, select, textarea")) return;
    const k = e.key;
    if (k === "Escape") closePanel();
    else if (k === "[") $("#back").click();
    else if (k === "]") $("#fwd").click();
    else if (k === "l") $("#live").click();
    else if (k === "/") { e.preventDefault(); $("#filter").focus(); }
    else if (k === "f") { e.preventDefault(); $("#search").focus(); }
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
    const changed = state.live !== wasLive;
    if (changed) setLive(state.live);
    if (!changed || !state.live) selectTab(state.tab);
    if (state.open) openEntity(state.open);
    else $("#panel").hidden = true;
  });
  search();
  selectTab(state.tab);
  if (state.live) setLive(true);
  // A link with open= starts with those details.
  if (state.open) openEntity(state.open);
}

init();
