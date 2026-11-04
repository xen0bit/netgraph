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
// when is a time in a row or a list: the time of day when the window makes the
// date obvious, else with it. A carried connection opened yesterday, or any
// row of a window several days long, would otherwise read as today.
const dayOf = (ms) => { const d = new Date(ms); return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}`; };
function when(ms) {
  const end = dayOf(state.to);
  if (dayOf(state.to - state.span) === end && dayOf(ms) === end) return clock(ms);
  const d = new Date(ms);
  return `${d.getFullYear() === new Date(state.to).getFullYear() ? "" : `${d.getFullYear()}-`}${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ${clock(ms)}`;
}
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
  // Flight Recorder: when on, the window ends at this moment and the event
  // rail shows what happened just before it.
  rec: { on: false, at: Date.now(), lookback: 5 * 60_000, follow: "", playing: false, diffA: 0 },
};

function loadHash() {
  const p = new URLSearchParams(location.hash.slice(1));
  const num = (k) => { const v = Number(p.get(k)); return Number.isFinite(v) ? v : null; };
  const to = num("to");
  if (to && to > 0) state.to = to;
  const span = num("span");
  if (span && span >= 10_000) state.span = span;
  if (p.get("from") && to) state.span = Math.max(10_000, state.to - Number(p.get("from")));
  state.live = p.get("live") === "1" || !p.has("to");
  state.filter = p.get("q") || "";
  if (p.get("tab") && tables[p.get("tab")]) state.tab = p.get("tab");
  if (p.get("layout") === "elk" || p.get("layout") === "dagre") state.layout = p.get("layout");
  for (const k of ["collapse", "dns", "sites", "anomalies", "networks", "identity"]) if (p.has(k)) state.gopts[k] = p.get(k) === "1";
  const top = num("top");
  if (top === -1 || (top && top >= 1)) state.gopts.top = Math.min(top, 1000);
  // sort=<table>.<column>.<asc|desc>
  state.sort = {};
  const [st, col, dir] = (p.get("sort") || "").split(".");
  if (tables[st] && tables[st].keys[Number(col)] && (dir === "asc" || dir === "desc")) state.sort[st] = { col: Number(col), dir };
  state.open = p.get("open") || "";
  state.rec.on = p.get("rec") === "1";
  const recAt = num("rec_at");
  if (recAt && recAt > 0) state.rec.at = recAt;
  const recLook = num("rec_lookback");
  if (recLook && recLook >= 10_000) state.rec.lookback = recLook;
  // Following is a Recorder mode: it filters every view, and only the Recorder
  // bar shows it and can end it.
  state.rec.follow = state.rec.on ? p.get("follow") || "" : "";
  if (state.rec.on) state.to = state.rec.at;
}

function saveHash() {
  const p = new URLSearchParams();
  if (state.live) { p.set("live", "1"); p.set("span", state.span); } else { p.set("from", state.to - state.span); p.set("to", state.to); }
  if (state.filter) p.set("q", state.filter);
  if (state.tab !== "graph") p.set("tab", state.tab);
  for (const k of ["collapse", "dns", "sites", "anomalies", "networks", "identity"]) p.set(k, state.gopts[k] ? "1" : "0");
  p.set("top", state.gopts.top);
  p.set("layout", state.layout);
  const so = state.sort[state.tab];
  if (so) p.set("sort", `${state.tab}.${so.col}.${so.dir}`);
  if (state.open) p.set("open", state.open);
  if (state.rec.on) {
    p.set("rec", "1");
    p.set("rec_at", state.rec.at);
    p.set("rec_lookback", state.rec.lookback);
    if (state.rec.follow) p.set("follow", state.rec.follow);
  }
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
  if (state.rec.follow) {
    const [kind, ...rest] = state.rec.follow.split(":");
    const key = rest.join(":");
    if (kind === "device") p.set("device", key);
    else if (kind === "domain" || kind === "site") p.set("domain", key);
    else if (kind === "ip") p.set("ip", key);
    else if (kind === "asn") p.set("asn", key);
  }
  return p;
}

// --- API ----------------------------------------------------------------------

// Storage can throw (private mode, sandboxed iframe, blocked cookies). The UI
// must still start without it; the token then lives for this page only.
const store = {
  get(k) { try { return localStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch { /* private mode */ } },
  remove(k) { try { localStorage.removeItem(k); } catch { /* private mode */ } },
};

let token = store.get("netgraph.token") || "";

async function api(path, extra = {}, raw = false) {
  let retried = false;
  for (;;) {
    const headers = token ? { Authorization: `Bearer ${token}` } : {};
    const resp = await fetch(`/api/v1/${path}?${params(extra)}`, { headers });
    if (resp.status === 401) {
      if (retried) {
        token = "";
        store.remove("netgraph.token")
        needAuth();
        throw new Error(`${path}: read token required`);
      }
      retried = true;
      if (!await askToken()) {
        needAuth();
        throw new Error(`${path}: read token required`);
      }
      continue;
    }
    if (!resp.ok) {
      let msg = resp.statusText;
      try { msg = (await resp.json()).error || msg; } catch { /* not JSON */ }
      throw new Error(`${path}: ${msg}`);
    }
    saveToken();
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
      if (retried) {
        token = "";
        store.remove("netgraph.token")
        needAuth();
        throw new Error("read token required");
      }
      retried = true;
      if (!await askToken()) {
        needAuth();
        throw new Error("read token required");
      }
      continue;
    }
    if (!resp.ok) {
      let msg = resp.statusText;
      try { msg = (await resp.json()).error || msg; } catch { /* not JSON */ }
      throw new Error(msg);
    }
    saveToken();
    if (resp.status === 204) return null;
    const ct = resp.headers.get("content-type") || "";
    return ct.includes("application/json") ? resp.json() : resp.text();
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
        // Saved only after the server accepts it in a real request.
        if (state.live) openLive();
      } else {
        needAuth();
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

function saveToken() {
  if (!token) return;
  store.set("netgraph.token", token)
  engine?.call("configure", { base: location.origin, token }).catch(() => {});
  $("#connect").hidden = true;
}

function needAuth() {
  setStatus("Read token required", true);
  $("#connect").hidden = false;
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
    if (/read token|401/.test(e.message)) needAuth();
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
  if (state.rec.on) state.rec.at = state.to;
  refresh();
}

// --- refresh ------------------------------------------------------------------

let refreshSeq = 0;
let entityReq = 0;
async function refresh() {
  if (state.live) state.to = Date.now();
  saveHash();
  renderWindow();
  const seq = ++refreshSeq;
  const cols = Math.max(Math.floor($("#spark").clientWidth / 3), 30);
  const step = Math.max(Math.floor(state.span / cols / 1000), 1) + "s";
  renderRecorder();
  // Each part draws when its answer arrives: the anomaly checks can take far
  // longer than a graph, which must not wait for them.
  const live = state.live;
  const headline = (async () => {
    const summaryP = track(api("summary")).catch(() => null);
    const anomaliesP = track(api("anomalies")).catch(() => null);
    const summary = await summaryP;
    if (seq !== refreshSeq) return;
    // Until this window's report arrives, Live keeps showing the last one
    // rather than flickering; any other window has no report yet.
    renderSummary(summary, live ? lastReport : null);
    const report = await anomaliesP;
    if (seq !== refreshSeq) return;
    lastReport = report;
    renderSummary(summary, report);
  })();
  const spark = track(api("timeseries", { step })).catch(() => null).then((s) => { if (seq === refreshSeq) renderSpark(s); });
  // An empty view offers a way to the data, so it needs to know where that is.
  const view = loadRange().then(() => (seq === refreshSeq ? renderTab(seq) : null));
  await Promise.all([headline, spark, view, state.rec.on ? renderRail(seq) : null]);
  if (seq === refreshSeq) renderRecorder();
}

let lastReport = null;

// --- what the server holds --------------------------------------------------------

// dataRange is GET /api/v1/range: where the Recorder's slider can go, and
// where to send someone looking at an empty window. A minute old is fresh
// enough for both.
let dataRange = null;
let dataRangeAt = 0;
let dataRangeReq = null;
function loadRange() {
  if (Date.now() - dataRangeAt < 60_000) return Promise.resolve(dataRange);
  if (dataRangeReq) return dataRangeReq;
  dataRangeReq = track(api("range")).then((r) => {
    dataRange = r;
    dataRangeAt = Date.now();
    return r;
  }).catch(() => dataRange).finally(() => { dataRangeReq = null; });
  return dataRangeReq;
}

const ago = (ms) => {
  if (ms < units.m) return "moments ago";
  for (const [n, v] of [["day", units.d], ["hour", units.h], ["minute", units.m]]) {
    if (ms >= v) { const c = Math.floor(ms / v); return `${c} ${n}${c === 1 ? "" : "s"} ago`; }
  }
  return "moments ago";
};

// emptyAction is what an empty window offers instead of a dead end: the way
// to data the server holds elsewhere, or the filter hiding it. All of it is
// our own text and numbers.
function emptyAction() {
  const r = dataRange;
  if (r && !r.last_ms) return ` No sensor has reported yet.`;
  const from = state.to - state.span;
  if (r && (r.last_ms < from || r.first_ms >= state.to)) {
    return ` <button type="button" class="empty-action" data-jump-latest>Latest data: ${esc(ago(Date.now() - r.last_ms))} →</button>`;
  }
  if (state.filter || state.rec.follow) return ` <button type="button" class="empty-action" data-clear-filter>Clear ${state.filter ? "filter" : "follow"}</button>`;
  return "";
}

// jumpToLatest moves the window, keeping its length, to end at the newest data.
function jumpToLatest() {
  if (!dataRange?.last_ms) return;
  const end = dataRange.last_ms + 1000;
  if (state.live) setLive(false);
  if (state.rec.on) setRecAt(end);
  else setWindow(end, state.span);
}

const tablePath = { devices: "devices", flows: "flows", destinations: "destinations", dns: "dns", facts: "facts", wifi: "wifi", sensors: "sensors", anomalies: "anomalies", incidents: "incidents" };

async function renderTab(seq) {
  const t = state.tab;
  try {
    if (t === "graph") return await renderGraph(seq);
    if (t === "insights") return await renderInsights(seq);
    const path = tablePath[t];
    const extra = state.limits[t] ? { limit: state.limits[t] } : {};
    if (t === "destinations" && $("#dest-group")?.value) extra.group = $("#dest-group").value;
    if (t === "incidents" && $("#incident-status")?.value) extra.status = $("#incident-status").value;
    let rows = await track(api(path, extra));
    if (seq !== refreshSeq) return;
    if (t === "anomalies") {
      const days = rows?.baseline_ms ? Math.round(rows.baseline_ms / 86400000) : 7;
      $("#anomaly-note").textContent = rows?.learning
        ? `Learning the network: history checks start after a day. Destination and traffic baselines look back ${days} days; only checks that need no history run now.`
        : `History checks active. Baselines look back ${days} days.`;
      rows = rows?.anomalies;
      const sev = $("#anomaly-sev")?.value;
      if (sev) rows = (rows || []).filter((a) => a.severity === sev);
      renderMutes();
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
      `${when(d.active_from)}–${when(d.active_to)}`,
    ],
    keys: [(d) => d.label, (d) => (d.randomized ? "private MAC" : d.vendor_short || d.vendor), (d) => addrKey(d.ips?.[0]),
      (d) => [...(d.hostnames || []), ...(d.services || [])].join(" "), (d) => d.flows, (d) => d.dns_queries, (d) => d.bytes_out,
      (d) => d.bytes_in, (d) => d.active_from],
    id: (d) => d.id,
    sort: (d) => -(d.bytes_in + d.bytes_out),
  },
  destinations: {
    cols: ["Destination", "Kind", "Connections", "Devices", "Sent", "Received", "First seen", "Last seen"],
    num: [2, 3, 4, 5],
    row: (d) => [esc(d.label) + (d.remote_ips?.length > 1 ? `<div class="sub">${esc(d.remote_ips.join(", "))}</div>` : ""),
      badge(d.kind) + (d.ports?.length ? `<div class="sub mono">${esc(d.ports.join(", "))}</div>` : ""),
      d.connections, d.devices, bytes(d.bytes_out), bytes(d.bytes_in), stamp(d.first_seen), stamp(d.last_seen)],
    keys: [(d) => d.label, (d) => d.kind, (d) => d.connections, (d) => d.devices, (d) => d.bytes_out, (d) => d.bytes_in, (d) => d.first_seen, (d) => d.last_seen],
    id: (d) => d.kind === "ip" ? `ip:${d.key}` : `domain:${d.key}`,
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
        when(f.first_seen),
        dirBadge(f.direction),
        client, `<span class="muted">→</span>`, server,
        esc(f.name) + (f.sni && f.qname && f.sni !== f.qname ? `<div class="sub">dns: ${esc(f.qname)}</div>` : ""),
        esc(f.app),
        badge(f.state, f.state) + (f.closed ? badge(f.truncated ? "truncated" : f.end_reason || "closed", "closed") : ""),
        bytes(f.bytes_out), bytes(f.bytes_in), when(f.last_seen),
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
      when(q.ts), esc(q.device_name || q.client_ip), esc(q.qtype),
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
  incidents: {
    cols: ["Opened", "Status", "Severity", "Kind", "Title", "Entities"],
    num: [],
    row: (i) => [stamp(i.opened), badge(i.status), badge(i.severity), esc(i.kind), esc(i.title), esc((i.entities || []).join(", "))],
    keys: [(i) => i.opened, (i) => i.status, (i) => i.severity, (i) => i.kind, (i) => i.title, (i) => (i.entities || []).join(" ")],
    id: (i) => `incident:${i.id}`,
  },
  sensors: {
    cols: ["Sensor", "Version", "Interfaces", "First seen", "Last seen", "Packets", "Kernel drops", "Active flows", "Evicted", "Queued", "Sent", "Send errors"],
    num: [5, 6, 7, 8, 9, 10, 11],
    row: (s) => [esc(s.name), esc(s.version), esc((s.interfaces || []).join(", ")), stamp(s.first_seen), stamp(s.last_seen),
      s.stats?.packets ?? "", s.stats?.kernel_drops ?? "", s.stats?.flows_active ?? "", s.stats?.flows_evicted ?? "",
      s.stats?.events_queued ?? "", s.stats?.batches_sent ?? "", s.stats?.send_errors ?? ""],
    keys: [(s) => s.name, (s) => s.version, (s) => (s.interfaces || []).join(" "), (s) => s.first_seen, (s) => s.last_seen,
      (s) => s.stats?.packets, (s) => s.stats?.kernel_drops, (s) => s.stats?.flows_active, (s) => s.stats?.flows_evicted,
      (s) => s.stats?.events_queued, (s) => s.stats?.batches_sent, (s) => s.stats?.send_errors],
    id: (s) => `sensor:${s.name}`,
  },
};

// What the API returns at most by default, and at most at all: past the
// default, "load more" doubles the request.
const limits = { flows: [1000, 100000], destinations: [1000, 100000], dns: [500, 50000], facts: [2000, 100000], wifi: [1000, 10000] };

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
  // Leading Unicode whitespace (including NBSP) hides a formula from a
  // simple prefix test; skip it before deciding.
  const lead = s.replace(/^[\s\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]+/, "");
  if (typeof v !== "number" && typeof v !== "boolean" && /^[=+\-@\t\r]/.test(lead)) s = "'" + s;
  return /[",\r\n]/.test(s) ? `"${s.replaceAll('"', '""')}"` : s;
}

// toCSV writes rows as the API returned them, every field, in the order
// the table shows them.
function toCSV(rows) {
  const cols = [];
  for (const r of rows) for (const k of Object.keys(r)) if (!cols.includes(k)) cols.push(k);
  return [cols.join(","), ...rows.map((r) => cols.map((k) => csvCell(k, r[k])).join(","))].join("\r\n") + "\r\n";
}

// renderMutes lists the mutes in force with a button that removes each.
async function renderMutes() {
  const box = $("#mutes");
  if (!box) return;
  let mutes = [];
  try { mutes = (await api("anomalies/mutes")).mutes || []; } catch { box.textContent = ""; return; }
  if (!mutes.length) { box.innerHTML = ""; return; }
  box.innerHTML = `<h3>Muted findings</h3><ul>${mutes.map((m) => `<li>${esc(m.kind || "any kind")} ${m.device ? esc(m.device) : ""} ${m.entity ? esc(m.entity) : ""} until ${stamp(m.until)} <button type="button" data-kind="${esc(m.kind)}" data-device="${esc(m.device)}" data-entity="${esc(m.entity)}">Unmute</button></li>`).join("")}</ul>`;
  for (const b of box.querySelectorAll("button")) {
    b.onclick = async () => {
      try {
        await send("DELETE", `anomalies/mute?kind=${encodeURIComponent(b.dataset.kind)}&device=${encodeURIComponent(b.dataset.device)}&entity=${encodeURIComponent(b.dataset.entity)}`);
        renderMutes();
      } catch (e) { setStatus(e.message); }
    };
  }
}

async function loadMore(t) {
  if (t === "destinations" && $("#dest-group")?.value) return;
  const [def, max] = limits[t] || [];
  const asked = state.limits[t] || def;
  if (!def || asked >= max) return;
  const next = Math.min(asked * 2, max);
  const offset = (state.data[t] || []).length;
  const seq = refreshSeq;
  try {
    const add = await track(api(tablePath[t], { limit: next - asked, offset }));
    if (seq !== refreshSeq) return;
    if (!Array.isArray(add) || add.length === 0) return;
    state.limits[t] = next;
    state.data[t] = [...(state.data[t] || []), ...add];
    renderTable(t);
  } catch { /* status shows it */ }
}

function exportAll(t) {
  if (!tablePath[t] || t === "sensors") return;
  return track(api("export", { kind: t, all: "1" }, true)).then((text) => {
    download(`netgraph-${t}-${fileStamp()}.csv`, text, "text/csv");
  }).catch(() => {});
}

// Incidents and sensors are not answers about the window: an empty list of
// them is not cured by moving it.
const windowed = (t) => t !== "incidents" && t !== "sensors";

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
  const grouped = t === "destinations" && $("#dest-group")?.value;
  more.hidden = !capped || asked >= max || Boolean(grouped);
  more.onclick = () => loadMore(t);
  tools.querySelector("[data-csv]").disabled = !rows.length;
  tools.querySelector("[data-csv]").onclick = () => download(`netgraph-${t}-${fileStamp()}.csv`, toCSV(rows), "text/csv");
  tools.querySelector("[data-copy-json]").onclick = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(rows, null, 2));
      setStatus(`${rows.length} rows copied`);
    } catch (e) { setStatus(`copy failed: ${e.message}`); }
  };
  const exportBtn = tools.querySelector("[data-export]");
  exportBtn.hidden = !tablePath[t] || t === "sensors";
  exportBtn.onclick = () => exportAll(t);
  el.onclick = (e) => {
    const b = e.target.closest("thead button.sort");
    if (b) sortBy(t, Number(b.dataset.col));
  };
  if (!rows.length) {
    el.innerHTML = head + `<tbody><tr><td class="empty" colspan="${spec.cols.length}">Nothing in this window.${windowed(t) ? emptyAction() : ""}</td></tr></tbody>`;
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
      <button data-copy-json title="Copy these rows as JSON">Copy JSON</button>
      <button data-export title="Download every row in this window, every field, as CSV">All CSV</button>
      <button data-csv title="Download these rows, every field, as CSV">CSV</button>`;
    table.before(tools);
  }
  return tools;
}

// --- graph ----------------------------------------------------------------------

let engine = null;
let engineState = "idle";
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
  if (state.layout === "dagre" && engineState === "idle") startEngine();
  if (engineState === "loading") {
    diagram.message(`Loading the graph engine…<div class="progress"><div id="wasm-progress"></div></div>`);
    await engineReady;
  }
  if (seq !== refreshSeq) return;
  diagram.loading("Loading graph…");
  const query = params(graphOpts()).toString();
  // What is being graphed, apart from Live moving the window forward: a
  // redraw of the same view keeps the person's pan and zoom.
  // Stepping or playing the Recorder is the same view at another moment.
  const moment = state.live ? state.span : state.rec.on ? ["recorder", state.rec.follow] : [state.to, state.span];
  const view = JSON.stringify([graphOpts(), state.filter, state.layout, moment]);
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
    diagram.message(`No activity in this window.${emptyAction()}`);
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

// The engine is several MB: it starts when a graph is first drawn, so a visit
// to the tables does not pay for it.
let engineReady = null;
function startEngine() {
  if (engineReady) return engineReady;
  engineState = "loading";
  engineReady = new Promise((resolve) => {
  try {
    engine = new Engine({
      onProgress: (loaded, total) => {
        const bar = document.getElementById("wasm-progress");
        if (bar) bar.style.width = total && loaded <= total ? `${(loaded / total) * 100}%` : "60%";
      },
      onReady: () => {
        engineState = "ready";
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
  return engineReady;
}

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

// --- insights -----------------------------------------------------------------------

async function renderInsights(seq) {
  const box = $("#insights-body");
  box.innerHTML = `<p class="muted">Reading exposure, coverage, airspace and weather…</p>`;
  try {
    const [exposure, coverage, airspace, weather] = await Promise.all([
      track(api("exposure")), track(api("coverage")), track(api("airspace")), track(api("weather")),
    ]);
    if (seq !== refreshSeq) return;
    const findings = (exposure?.findings || []).map((f) => `<li>${badge(f.severity)} <b>${esc(f.kind.replaceAll("_", " "))}</b> ${esc(f.summary)}</li>`).join("");
    const sensors = (coverage?.sensors || []).map((s) => `<tr><td>${esc(s.name)}</td><td>${s.devices}</td><td>${s.only_device}</td><td>${stamp(s.last_seen)}</td></tr>`).join("");
    const only = (coverage?.devices || []).filter((d) => d.only_one).slice(0, 20).map((d) => `<li>${esc(d.label)} <span class="muted">only by ${esc(d.sensors.join(", "))}</span></li>`).join("");
    const nets = (airspace?.networks || []).slice(0, 50).map((n) => `<tr><td class="mono">${esc(n.bssid)}</td><td>${esc(n.ssid)}</td><td>${esc(n.security || "unknown")}</td><td>${n.channel}</td><td>${(n.clients || []).length}</td><td>${n.rogue ? badge("rogue", "sev-high") : ""}</td></tr>`).join("");
    const pts = (weather?.points || []);
    // A forecast has no bytes of its own: it is drawn as its band's top.
    const level = (p) => (p.forecast ? p.upper || 0 : p.bytes_out + p.bytes_in);
    const max = Math.max(1, ...pts.map(level));
    const bars = pts.map((p) => `<span class="wbar${p.forecast ? " forecast" : ""}" title="${stamp(p.ts)} ${p.forecast ? `forecast ${bytes(p.lower || 0)} to ${bytes(p.upper || 0)}` : bytes(p.bytes_out + p.bytes_in)}" style="height:${Math.max(2, (level(p) / max) * 54)}px"></span>`).join("");
    box.innerHTML = `<div class="insight-grid">
      <section class="card"><h3>Exposure</h3><p class="muted">Reachable or weak things, from evidence.</p><ul class="tight">${findings || "<li class=\"muted\">Nothing stands out.</li>"}</ul>${(exposure?.gaps || []).map((g) => `<p class="muted">${esc(g)}</p>`).join("")}</section>
      <section class="card"><h3>Sensor coverage</h3><table class="mini"><thead><tr><th>Sensor</th><th>Devices</th><th>Only seen</th><th>Last seen</th></tr></thead><tbody>${sensors}</tbody></table>${only ? `<h4>Only one sensor saw</h4><ul class="tight">${only}</ul>` : ""}<p class="muted">Coverage is where traffic was observed, not an RF survey.</p></section>
      <section class="card"><h3>Wi-Fi airspace</h3><table class="mini"><thead><tr><th>BSSID</th><th>SSID</th><th>Security</th><th>Ch</th><th>Clients</th><th></th></tr></thead><tbody>${nets || "<tr><td colspan=\"6\" class=\"muted\">No monitor-mode Wi-Fi data.</td></tr>"}</tbody></table></section>
      <section class="card"><h3>Network weather</h3><div class="weather">${bars}</div><p class="muted">${weather ? `${pts.length} buckets · ${fmtSpan(weather.step_ms)} · the last six are a moving-mean forecast with a band` : "No traffic data."}</p>${(weather?.gaps || []).map((g) => `<p class="muted">${esc(g)}</p>`).join("")}</section>
    </div>`;
  } catch (e) {
    box.innerHTML = `<p class="muted">${esc(e.message)}</p>`;
  }
}

// --- entity panel -------------------------------------------------------------------

async function openEntity(id, { anomaly } = {}) {
  if (!id) return;
  if (id.startsWith("incident:")) return openIncident(Number(id.slice("incident:".length)));
  const req = ++entityReq;
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
    if (req === entityReq) $("#panel-body").innerHTML = `<h2>${esc(id)}</h2><p class="muted">${esc(e.message)}</p>`;
    return;
  }
  if (req !== entityReq) return;
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
    return `<li><time>${when(f.first_seen)}–${when(f.last_seen)}</time>${badge(f.rel)} ${out ? "→" : "←"} ${out ? link(f.dst, f.dst_label) : link(f.src, f.src_label)} <span class="muted">×${f.count} ${esc(f.source)}</span></li>`;
  }).join("");
  // Each connection as client → server; the peer (what the device talked
  // to, or the client that reached it) links to its details.
  const flows = (d.flows || []).slice(0, 100).map((f) => {
    const dev = esc(f.device_name || (f.direction === "in" ? f.server_ip : f.client_ip));
    const line = f.direction === "in"
      ? `${link(peerID(f), hostPort(f.client_ip, f.client_port))} → ${dev}:${f.server_port}/${esc(f.proto)}${f.name ? ` <span class="muted">for ${esc(f.name)}</span>` : ""}`
      : `${dev} → ${link(peerID(f), f.name || f.server_ip)}:${f.server_port}/${esc(f.proto)}`;
    return `<li><time>${when(f.first_seen)}</time>${dirBadge(f.direction)} ${line} ${badge(f.state, f.state)}${f.closed ? badge(f.end_reason, "closed") : ""} <span class="muted">sent ${bytes(f.bytes_out)} · received ${bytes(f.bytes_in)}</span></li>`;
  }).join("");
  const timeline = (d.timeline || []).slice(-300).map((e) => `<li><time>${when(e.ts)}</time>${badge(e.type)} ${esc(e.detail)}</li>`).join("");
  const flagged = anomaly
    ? [anomaly.summary, ...Object.entries(anomaly.evidence || {}).map(([k, v]) => `${k}: ${v}`)]
    : state.graph?.nodes?.find((n) => n.id === id)?.attrs?.anomalies?.split("\n");
  const anomalyBox = flagged ? `<div class="anomaly-box"><b>${anomaly ? `${esc(anomaly.severity)} ${esc(anomaly.kind.replaceAll("_", " "))}` : "Anomalies"}</b><ul>${flagged.map((l) => `<li>${esc(l)}</li>`).join("")}</ul>${anomaly ? `<button type="button" id="autopsy-anomaly">Autopsy</button> <button type="button" id="save-incident">Save incident</button> <button type="button" id="mute-anomaly">Mute this for 1 hour</button>` : ""}</div>` : "";
  $("#panel-body").innerHTML = `${anomalyBox}
    <h2>${esc(d.label || d.key)}</h2>
    <div class="muted mono">${esc(d.id)}</div>${rename}
    <dl><dt>first seen</dt><dd>${stamp(d.first_seen)}</dd><dt>last seen</dt><dd>${stamp(d.last_seen)}</dd>${devInfo}${attrs}</dl>
    ${facts ? `<h3>Relationships in this window</h3><ul>${facts}</ul>` : ""}
    ${flows ? `<h3>Connections</h3><ul>${flows}</ul>` : ""}
    ${timeline ? `<h3>Timeline</h3><ul>${timeline}</ul>` : ""}
    <p><a data-filter="${esc(filterFor(d))}">Filter the window to this ${esc(d.kind)}</a> · <a data-follow="${esc(d.id)}">Follow in Recorder</a></p>`;
  $("#autopsy-anomaly")?.addEventListener("click", async (e) => {
    e.target.disabled = true;
    try {
      const a = await track(api("autopsy", {
        kind: anomaly.kind, severity: anomaly.severity, ts: anomaly.ts,
        device: anomaly.device || "", entity: anomaly.entity || "", summary: anomaly.summary || "",
        evidence: JSON.stringify(anomaly.evidence || {}),
      }));
      renderAutopsy(a);
    } catch (err) {
      setStatus(err.message, true);
    } finally {
      e.target.disabled = false;
    }
  });
  $("#save-incident")?.addEventListener("click", async (e) => {
    e.target.disabled = true;
    try {
      const inc = await send("POST", "incidents", { anomaly, title: anomaly.summary || anomaly.kind });
      setStatus(`incident #${inc.id} saved`);
    } catch (err) {
      e.target.disabled = false;
      setStatus(err.message, true);
    }
  });
  $("#mute-anomaly")?.addEventListener("click", async (e) => {
    e.target.disabled = true;
    try {
      await send("POST", "anomalies/mute", { kind: anomaly.kind, device: anomaly.device || "", entity: anomaly.entity || "",
        until: Date.now() + 3600_000, note: "muted from web UI" });
      setStatus("anomaly muted for 1 hour");
      closePanel();
      refresh();
    } catch (err) {
      e.target.disabled = false;
      setStatus(err.message, true);
    }
  });
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
    if (a.dataset.follow) { follow(a.dataset.follow); }
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
    if (a.dataset.follow) { follow(a.dataset.follow); }
    if (a.dataset.filter) { state.filter = a.dataset.filter; $("#filter").value = state.filter; refresh(); }
  };
}

// --- live ---------------------------------------------------------------------------

let liveFeed = null;
let liveTimer = null;
let pending = null;

// Batches arrive every couple of seconds; refresh at most that often.
function onIngest() {
  if (!pending) pending = setTimeout(() => { pending = null; refresh(); }, 2000);
}

function closeLive() {
  liveFeed?.abort();
  liveFeed = null;
}

function openLive() {
  closeLive();
  liveFeed = new AbortController();
  followLive(liveFeed.signal);
}

// followLive reads the server-sent events with fetch rather than EventSource,
// which cannot set a header and would put the token in a URL, where proxies
// log it. Like EventSource it reconnects, backing off while the server is away.
async function followLive(signal) {
  let delay = 1000;
  while (!signal.aborted) {
    try {
      const headers = { Accept: "text/event-stream" };
      if (token) headers.Authorization = `Bearer ${token}`;
      const resp = await fetch("/api/v1/live", { headers, signal, cache: "no-store" });
      if (resp.status === 401) { needAuth(); return; }
      if (!resp.ok || !resp.body) throw new Error(`live: ${resp.status}`);
      delay = 1000;
      const reader = resp.body.pipeThrough(new TextDecoderStream()).getReader();
      let buf = "";
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += value;
        for (let i = buf.indexOf("\n\n"); i >= 0; i = buf.indexOf("\n\n")) {
          if (/^event: ingest$/m.test(buf.slice(0, i))) onIngest();
          buf = buf.slice(i + 2);
        }
        // Only ever a partial frame: a server sending no frame end is not one.
        if (buf.length > 4 << 20) throw new Error("live: oversized event");
      }
    } catch { /* reconnect below, unless this was closed */ }
    if (signal.aborted) return;
    await new Promise((r) => setTimeout(r, delay));
    delay = Math.min(delay * 2, 30_000);
  }
}

function setLive(on) {
  state.live = on;
  if (on && state.rec.on) {
    state.rec.on = false;
    state.rec.follow = "";
    stopPlay();
    $("#recorder-bar").hidden = true;
    $("#event-rail").hidden = true;
    $("#recorder").setAttribute("aria-pressed", "false");
  }
  closeLive();
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

// --- notes and bookmarks --------------------------------------------------------------

function openNote() {
  const dlg = $("#note-dialog");
  $("#note-text").value = "";
  $("#note-entity").value = state.rec.follow || state.open || "";
  $("#note-status").textContent = stamp(state.to);
  if (!dlg.open) dlg.showModal();
  setTimeout(() => $("#note-text").focus(), 0);
}

async function saveNote() {
  const text = $("#note-text").value.trim();
  if (!text) { $("#note-status").textContent = "write something first"; return; }
  try {
    await send("POST", "annotations", { ts: state.to, entity: $("#note-entity").value.trim(), kind: "note", text, author: "web" });
    $("#note-dialog").close();
    setStatus("note saved");
    refresh();
  } catch (e) {
    $("#note-status").textContent = e.message;
  }
}

async function exportCapsule() {
  try {
    const html = await track(api("capsule", { from: state.to - state.span, to: state.to }, true));
    download(`netgraph-capsule-${fileStamp()}.html`, html, "text/html");
    setStatus("capsule downloaded");
  } catch (e) {
    setStatus(e.message, true);
  }
}

// inputDialog is the app's own prompt or confirm: it does not block the page,
// and works where browsers suppress native dialogs. Without `input` it only
// confirms. It resolves to the text (or true), or null if cancelled.
let inputDialogBusy = null;
function inputDialog({ title, text = "", input = false, placeholder = "", ok = "OK", danger = false }) {
  if (inputDialogBusy) return inputDialogBusy;
  const dlg = $("#input-dialog"), field = $("#input-dialog-value"), okBtn = $("#input-dialog-ok");
  $("#input-dialog-title").textContent = title;
  $("#input-dialog-text").textContent = text;
  $("#input-dialog-text").hidden = !text;
  field.hidden = !input;
  field.required = input;
  field.value = "";
  field.placeholder = placeholder;
  okBtn.textContent = ok;
  okBtn.classList.toggle("danger", danger);
  dlg.returnValue = "";
  inputDialogBusy = new Promise((resolve) => {
    dlg.addEventListener("close", () => {
      inputDialogBusy = null;
      if (dlg.returnValue !== "ok") return resolve(null);
      resolve(input ? field.value.trim() || null : true);
    }, { once: true });
    dlg.showModal();
    if (input) field.focus(); else okBtn.focus();
  });
  return inputDialogBusy;
}

async function saveBookmark() {
  const at = state.to;
  const name = await inputDialog({ title: "Bookmark this moment", text: stamp(at), input: true, placeholder: "What is this moment?", ok: "Save bookmark" });
  if (!name) return;
  try {
    await send("POST", "bookmarks", { ts: at, entity: state.rec.follow || state.open || "", name });
    setStatus("bookmark saved");
    refresh();
  } catch (e) {
    setStatus(e.message, true);
  }
}

// --- what-if -------------------------------------------------------------------------

const whatifExample = {
  version: 1,
  zones: [{ name: "all", devices: ["any"] }],
  defaults: { egress: "deny", ingress: "deny", intra_zone: "allow", dns: "allow" },
  rules: [
    { name: "web", from: "zone:all", to: "any", ports: ["443/tcp", "80/tcp"], action: "allow" },
    { name: "dns", from: "zone:all", to: "any", ports: ["53/tcp", "53/udp"], action: "allow" },
  ],
  dns: { block: [], allow: [] },
};

function openWhatIf() {
  const dlg = $("#whatif-dialog");
  $("#whatif-policy").value = JSON.stringify(whatifExample, null, 2);
  $("#whatif-result").innerHTML = "";
  $("#whatif-status").textContent = "";
  if (!dlg.open) dlg.showModal();
}

async function runWhatIf() {
  const status = $("#whatif-status"), box = $("#whatif-result");
  let policy;
  try {
    policy = JSON.parse($("#whatif-policy").value);
  } catch (e) {
    status.textContent = `invalid JSON: ${e.message}`;
    return;
  }
  status.textContent = "Simulating…";
  box.innerHTML = "";
  try {
    const r = await send("POST", "whatif", { policy, from: String(state.to - state.span), to: String(state.to) });
    const s = r.summary || {};
    status.textContent = `${s.connections || 0} connections evaluated`;
    const impact = (x) => `<li><b>${esc(x.device_name || "unknown device")}</b> → ${esc(x.destination || "?")} <span class="mono">${esc(x.port || "")}</span> <span class="muted">${esc(x.reason || "")}${x.rule ? ` (${esc(x.rule)})` : ""}</span></li>`;
    box.innerHTML = `<p><b>${s.blocked || 0}</b> blocked (<b>${s.essential || 0}</b> essential), <b>${s.lookups || 0}</b> lookups blocked, <b>${s.unknown || 0}</b> unknown, <b>${s.unchanged || 0}</b> unchanged.</p>
      ${(r.essential || []).length ? `<h3>Essential dependencies</h3><ul>${r.essential.map(impact).join("")}</ul>` : ""}
      ${(r.blocked || []).length ? `<h3>Would be blocked</h3><ul>${r.blocked.slice(0, 100).map(impact).join("")}</ul>` : ""}
      ${(r.unknown || []).length ? `<h3>Unknown</h3><ul>${r.unknown.slice(0, 50).map(impact).join("")}</ul>` : ""}
      ${(r.gaps || []).map((g) => `<p class="muted">gap: ${esc(g)}</p>`).join("")}`;
  } catch (e) {
    status.textContent = e.message;
  }
}

// --- ask -----------------------------------------------------------------------------

function renderAnswer(a) {
  const box = $("#ask-answer");
  box.innerHTML = `<p><b>${esc(a.answer || "No answer.")}</b></p>
    ${(a.claims || []).map((c) => `<p>${esc(c.text)} ${(c.evidence || []).map((e) => `<button class="cite" data-kind="${esc(e.kind)}" data-id="${esc(e.id)}" data-ts="${e.ts || 0}">${esc(e.kind)}</button>`).join(" ")}</p>`).join("")}
    ${(a.gaps || []).length ? `<p class="muted">Gaps: ${esc(a.gaps.join("; "))}</p>` : ""}
    ${(a.plan || []).length ? `<details><summary>How I answered</summary><ol>${a.plan.map((p) => `<li><span class="badge">${esc(p.tool)}</span> ${esc(Object.entries(p.args || {}).map(([k, v]) => `${k}=${v}`).join(" "))}</li>`).join("")}</ol></details>` : ""}
    ${(a.followups || []).length ? `<p class="muted">Try: ${a.followups.map(esc).join(" · ")}</p>` : ""}`;
  box.querySelectorAll(".cite").forEach((b) => {
    b.onclick = () => {
      const kind = b.dataset.kind, id = b.dataset.id, ts = Number(b.dataset.ts);
      if (kind === "entity") openEntity(id);
      else if (ts) { toggleRecorder(true); setRecAt(ts); }
      $("#ask-dialog").close();
    };
  });
}

function openAsk() {
  const dlg = $("#ask-dialog");
  $("#ask-q").value = "";
  $("#ask-answer").innerHTML = `<p class="muted">Ask about a device, a name, a moment, an anomaly, or what changed.</p>`;
  if (!dlg.open) dlg.showModal();
  setTimeout(() => $("#ask-q").focus(), 0);
}

// --- autopsy -------------------------------------------------------------------------

async function openIncident(id) {
  try {
    const [a, d] = await Promise.all([track(api(`incidents/${id}/autopsy`)), track(api(`incidents/${id}`))]);
    renderAutopsy(a, d);
  } catch (e) {
    setStatus(e.message, true);
  }
}

// What a saved incident adds to its reel: its status, its notes and the
// buttons that change them.
function incidentTools(d) {
  const next = { acknowledge: "acknowledged", resolve: "resolved", reopen: "open" };
  const buttons = Object.entries(next).filter(([, s]) => s !== d.status)
    .map(([verb, s]) => `<button type="button" data-status="${s}">${verb[0].toUpperCase() + verb.slice(1)}</button>`).join(" ");
  const notes = (d.notes || []).map((n) => `<li><time>${stamp(n.ts)}</time> ${esc(n.body)}</li>`).join("");
  return `<div class="incident-tools">
    <p>${badge(d.status)} ${esc(d.title)}</p>
    ${notes ? `<ul class="evidence">${notes}</ul>` : ""}
    <div class="actions">
      ${buttons}
      <input id="incident-note" type="text" aria-label="Add a note to this incident" placeholder="Add a note">
      <button type="button" id="incident-note-save">Add note</button>
      <button type="button" id="incident-export">Export</button>
      <button type="button" id="incident-delete">Delete</button>
    </div>
  </div>`;
}

function wireIncidentTools(d) {
  const box = $("#autopsy-body");
  const update = async (body) => {
    try {
      await send("PATCH", `incidents/${d.id}`, body);
      await openIncident(d.id);
      refresh();
    } catch (e) {
      setStatus(e.message, true);
    }
  };
  box.querySelectorAll("[data-status]").forEach((b) => { b.onclick = () => update({ status: b.dataset.status }); });
  $("#incident-note-save").onclick = () => {
    const note = $("#incident-note").value.trim();
    if (note) update({ note, author: "web" });
  };
  $("#incident-export").onclick = async () => {
    try {
      download(`netgraph-incident-${d.id}.json`, await track(api(`incidents/${d.id}/export`, {}, true)), "application/json");
    } catch (e) {
      setStatus(e.message, true);
    }
  };
  $("#incident-delete").onclick = async () => {
    if (!await inputDialog({ title: `Delete incident #${d.id}?`, text: "Its notes and pinned evidence go with it.", ok: "Delete", danger: true })) return;
    try {
      await send("DELETE", `incidents/${d.id}`);
      $("#autopsy-dialog").close();
      refresh();
    } catch (e) {
      setStatus(e.message, true);
    }
  };
}

function renderAutopsy(a, incident) {
  const dlg = $("#autopsy-dialog");
  $("#autopsy-title").textContent = `${a.anomaly?.kind?.replaceAll("_", " ") || (a.incident ? `Incident #${a.incident}` : "Incident")} autopsy`;
  $("#autopsy-meta").textContent = `${stamp(a.from)} → ${stamp(a.to)} · ${a.scenes?.length || 0} scenes`;
  const scenes = (a.scenes || []).map((s, i) => `<article class="scene" data-at="${s.at}">
    <h3>${i + 1}. ${esc(s.title)}</h3>
    <p>${esc(s.narrative)}</p>
    ${(s.evidence || []).length ? `<ul class="evidence">${s.evidence.map((e) => `<li><span class="badge">${esc(e.kind)}</span> ${esc(e.text || e.id)}</li>`).join("")}</ul>` : ""}
    <button type="button" data-open="${s.at}">Open this moment</button>
  </article>`).join("");
  $("#autopsy-body").innerHTML = (incident ? incidentTools(incident) : "") + scenes + (a.gaps || []).map((g) => `<p class="muted">gap: ${esc(g)}</p>`).join("");
  if (incident) wireIncidentTools(incident);
  $("#autopsy-body").querySelectorAll("[data-open]").forEach((b) => {
    b.onclick = () => {
      const ts = Number(b.dataset.open);
      if (ts) { toggleRecorder(true); setRecAt(ts); }
      dlg.close();
    };
  });
  if (!dlg.open) dlg.showModal();
}

// --- Flight Recorder ------------------------------------------------------------------

let recTimer = null;
let recSeek = null;

function renderRecorder() {
  const bar = $("#recorder-bar");
  if (!bar) return;
  $("#recorder").setAttribute("aria-pressed", String(state.rec.on));
  bar.hidden = !state.rec.on;
  $("#event-rail").hidden = !state.rec.on;
  if (!state.rec.on) return;
  const now = Date.now();
  const head = $("#rec-head");
  // What the server holds, always including where the Recorder is now. With
  // nothing known yet it is the last day, not a guess at retention.
  const lo = Math.min(dataRange?.first_ms || now - units.d, state.to);
  const hi = Math.max(now, state.to);
  head.min = String(lo);
  head.max = String(hi);
  head.step = "1000";
  head.value = String(state.to);
  renderDensity(lo, hi);
  $("#rec-time").textContent = stamp(state.to);
  $("#rec-play").textContent = state.rec.playing ? "❚❚" : "▶";
  $("#rec-lookback").value = String(state.rec.lookback);
  const f = $("#rec-follow");
  f.hidden = !state.rec.follow;
  f.textContent = state.rec.follow ? `Following ${state.rec.follow}` : "";
  $("#rec-unfollow").hidden = !state.rec.follow;
  $("#rec-diff").textContent = state.rec.diffA ? "Diff B" : "Diff A";
  if (state.live) $("#rec-time").textContent += " · live edge";
}

// renderDensity draws where the traffic is behind the slider, so the eye can
// find the moments worth seeking to. It is drawn from a series fetched at most
// once a minute for a given range: the shape does not change as the head moves.
let density = { key: "", at: 0, series: null, loading: false };
function renderDensity(lo, hi) {
  const c = $("#rec-density");
  if (!c) return;
  const key = `${lo}|${state.filter}|${state.rec.follow}`;
  const stale = density.key !== key || Date.now() - density.at > 60_000;
  if (stale && !density.loading && c.clientWidth > 0) {
    density.loading = true;
    const buckets = Math.max(Math.floor(c.clientWidth / 3), 30);
    const step = Math.max(Math.ceil((hi - lo) / buckets / 1000), 60);
    api("timeseries", { from: lo, to: hi, step: `${step}s` })
      .then((s) => { density = { key, at: Date.now(), series: s, loading: false }; })
      .catch(() => { density = { ...density, key, at: Date.now(), loading: false }; })
      .then(() => renderDensity(lo, hi));
  }
  const dpr = window.devicePixelRatio || 1;
  const W = c.clientWidth, H = c.clientHeight;
  c.width = W * dpr;
  c.height = H * dpr;
  const g = c.getContext("2d");
  g.scale(dpr, dpr);
  const bs = density.series?.buckets;
  if (!bs?.length || hi <= lo) return;
  const peak = Math.max(1, ...bs.map((b) => b.bytes_in + b.bytes_out));
  g.fillStyle = getComputedStyle(document.documentElement).getPropertyValue("--accent").trim() || "#2563eb";
  const step = density.series.step || density.series.step_ms || 0;
  for (const b of bs) {
    const v = b.bytes_in + b.bytes_out;
    if (!v) continue;
    // Square-rooted: one huge transfer must not flatten every other moment.
    const h = Math.max(2, Math.sqrt(v / peak) * H);
    const x0 = ((b.ts - lo) / (hi - lo)) * W, x1 = ((b.ts + step - lo) / (hi - lo)) * W;
    g.fillRect(x0, H - h, Math.max(x1 - x0, 1), h);
  }
}

function setRecAt(ts) {
  state.rec.at = Math.max(0, Math.round(ts));
  state.to = state.rec.at;
  state.span = state.rec.lookback;
  state.live = false;
  return refresh();
}

let playRun = 0;
function stopPlay() {
  state.rec.playing = false;
  playRun++;
  clearTimeout(recTimer);
  recTimer = null;
  renderRecorder();
}

// togglePlay starts a loop that waits for each moment to be drawn before asking
// for the next, so a slow server gets fewer frames rather than a pile of
// requests. The head advances by the time that really passed, so the speed
// stays true however few frames there are.
function togglePlay() {
  if (state.rec.playing) return stopPlay();
  state.rec.playing = true;
  state.rec.at = Math.min(state.rec.at, Date.now());
  const run = ++playRun;
  let last = performance.now();
  const tick = async () => {
    if (run !== playRun) return;
    const started = performance.now();
    const speed = Number($("#rec-speed").value) || 1;
    const next = state.rec.at + (started - last) * speed;
    last = started;
    if (next >= Date.now()) {
      setRecAt(Date.now());
      stopPlay();
      return;
    }
    await setRecAt(next);
    if (run !== playRun) return;
    recTimer = setTimeout(tick, Math.max(0, 1000 - (performance.now() - started)));
  };
  recTimer = setTimeout(tick, 1000);
  renderRecorder();
}

function toggleRecorder(on = !state.rec.on) {
  state.rec.on = on;
  if (on) {
    // Start from the moment on screen, not wherever the recorder last was.
    state.rec.at = Math.min(state.to, Date.now());
    state.to = state.rec.at;
    // The smallest frame that still holds the window on screen: narrowing an
    // hour with data in it to its last five minutes could show nothing.
    state.rec.lookback = [5, 15, 60].map((m) => m * units.m).find((v) => v >= state.span) ?? units.h;
    state.span = state.rec.lookback;
    if (state.live) setLive(false);
    state.live = false;
  } else {
    // Following filters every view, and its controls are leaving with the bar.
    state.rec.follow = "";
    stopPlay();
  }
  renderRecorder();
  refresh();
}

function follow(id) {
  if (!id) return;
  state.rec.follow = id;
  state.rec.on = true;
  state.rec.at = state.to;
  state.rec.lookback = state.span > 0 && state.span <= units.h ? state.span : 5 * units.m;
  state.span = state.rec.lookback;
  state.live = false;
  renderRecorder();
  refresh();
}

async function renderRail(seq) {
  const box = $("#event-rail");
  if (!box) return;
  if (!state.rec.on) { box.hidden = true; return; }
  box.hidden = false;
  let page;
  try {
    // Flows and lookups are the bulk of the rail and would push a note out of
    // the last forty events within seconds on a busy network.
    const kinds = $("#rec-rail").value === "all" ? "" : "annotation,bookmark,device_new,observation";
    page = await track(api("timeline", { from: state.to - units.d, to: state.to + 1, limit: 40, entity: state.rec.follow || "", kinds }));
  } catch (e) {
    box.innerHTML = `<p class="muted">${esc(e.message)}</p>`;
    return;
  }
  if (seq !== refreshSeq) return;
  const events = page?.events || [];
  if (!events.length) {
    box.innerHTML = `<div class="rail-head"><b>Events</b><span class="muted">nothing recorded in the last day</span></div>`;
    return;
  }
  box.innerHTML = `<div class="rail-head"><b>Events</b><span class="muted">last day · click to jump</span></div>
    <ul class="rail-list">${events.map((e) => `<li><button class="rail-event" data-ts="${e.ts}" data-entity="${esc(e.entity || "")}">
      <time>${when(e.ts)}</time> ${badge(e.kind)} ${esc(e.title)}</button></li>`).join("")}</ul>`;
  box.querySelectorAll(".rail-event").forEach((b) => {
    b.onclick = () => {
      const ts = Number(b.dataset.ts);
      if (ts) setRecAt(ts);
      if (b.dataset.entity) openEntity(b.dataset.entity);
    };
  });
}

async function renderDiffBox() {
  const box = $("#event-rail");
  if (!state.rec.diffA) {
    state.rec.diffA = state.to;
    setStatus(`diff A marked at ${stamp(state.to)}`);
    renderRecorder();
    return;
  }
  const a = state.rec.diffA;
  state.rec.diffA = 0;
  box.hidden = false;
  box.innerHTML = `<div class="rail-head"><b>Diff</b><span class="muted">${esc(stamp(a))} → ${esc(stamp(state.to))}</span></div><p class="muted">Comparing…</p>`;
  try {
    const d = await api("diff", { at_a: a, at_b: state.to, lookback: state.rec.lookback });
    const row = (kind, x) => `<li><span class="badge">${esc(kind)}</span> <b>${esc(x.kind)}</b> ${esc(x.label || x.key)}${x.before || x.after ? ` <span class="muted">${esc(x.before || "")}${x.before && x.after ? " → " : ""}${esc(x.after || "")}</span>` : ""}</li>`;
    const lines = [
      ...(d.added || []).map((x) => row("added", x)),
      ...(d.removed || []).map((x) => row("removed", x)),
      ...(d.changed || []).map((x) => row("changed", x)),
    ];
    box.innerHTML = `<div class="rail-head"><b>Diff</b><span class="muted">${esc(stamp(a))} → ${esc(stamp(state.to))}</span></div>
      ${lines.length ? `<ul class="rail-list">${lines.join("")}</ul>` : `<p class="muted">No differences in devices, destinations, DNS, Wi-Fi, sensors or anomalies.</p>`}
      ${(d.gaps || []).map((g) => `<p class="muted">gap: ${esc(g)}</p>`).join("")}`;
  } catch (e) {
    box.innerHTML = `<p class="muted">${esc(e.message)}</p>`;
  }
  renderRecorder();
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
    if (q.length < 2) { seq++; clearTimeout(timer); results = []; close(); return; }
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
  fetch("/api/v1/version").then((r) => r.json()).then((v) => { $("#version").textContent = `netgraph ${v.version}`; }).catch(() => {});
  document.addEventListener("click", (e) => {
    if (e.target.closest("[data-jump-latest]")) jumpToLatest();
    else if (e.target.closest("[data-clear-filter]")) {
      state.filter = "";
      $("#filter").value = "";
      state.rec.follow = "";
      refresh();
    }
  });
  const saved = store.get("netgraph.theme");
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
  $("#recorder").onclick = () => toggleRecorder();
  $("#rec-play").onclick = togglePlay;
  $("#rec-back").onclick = () => setRecAt(state.rec.at - Math.max(1000, state.rec.lookback / 5));
  $("#rec-fwd").onclick = () => setRecAt(Math.min(Date.now(), state.rec.at + Math.max(1000, state.rec.lookback / 5)));
  $("#rec-now").onclick = () => setRecAt(Date.now());
  $("#rec-note").onclick = openNote;
  $("#rec-bookmark").onclick = saveBookmark;
  $("#rec-capsule").onclick = exportCapsule;
  $("#note-save").onclick = saveNote;
  $("#rec-diff").onclick = renderDiffBox;
  $("#rec-unfollow").onclick = () => { state.rec.follow = ""; refresh(); };
  $("#rec-head").oninput = () => {
    clearTimeout(recSeek);
    const ts = Number($("#rec-head").value);
    recSeek = setTimeout(() => setRecAt(ts), 120);
  };
  $("#rec-lookback").onchange = () => {
    state.rec.lookback = Number($("#rec-lookback").value) || 300000;
    setRecAt(state.rec.at);
  };
  $("#rec-rail").onchange = () => refresh();
  $("#rec-speed").onchange = () => { if (state.rec.playing) { stopPlay(); togglePlay(); } };
  for (const b of $$(".presets button")) b.onclick = () => setWindow(Date.now(), parseSpan(b.dataset.span), { live: state.live });
  const fromTo = () => {
    const f = new Date($("#from").value).getTime(), t = new Date($("#to").value).getTime();
    if (f < t) setWindow(t, t - f);
  };
  $("#from").onchange = fromTo;
  $("#to").onchange = fromTo;
  let typing;
  $("#filter").oninput = () => { clearTimeout(typing); typing = setTimeout(() => { state.filter = $("#filter").value; refresh(); }, 400); };
  const tabButtons = $$(".tabs button");
  for (const [i, b] of tabButtons.entries()) {
    b.onclick = () => selectTab(b.dataset.tab);
    b.onkeydown = (e) => {
      if (e.key !== "ArrowRight" && e.key !== "ArrowLeft" && e.key !== "Home" && e.key !== "End") return;
      e.preventDefault();
      const n = e.key === "Home" ? 0 : e.key === "End" ? tabButtons.length - 1
        : (i + (e.key === "ArrowRight" ? 1 : -1) + tabButtons.length) % tabButtons.length;
      tabButtons[n].focus();
      selectTab(tabButtons[n].dataset.tab);
    };
  }
  $("#summary").onclick = (e) => { const a = e.target.closest("[data-tab]"); if (a) selectTab(a.dataset.tab); };
  for (const [id, k] of [["#g-collapse", "collapse"], ["#g-dns", "dns"], ["#g-sites", "sites"], ["#g-anomalies", "anomalies"], ["#g-networks", "networks"], ["#g-identity", "identity"]]) {
    $(id).onchange = () => { state.gopts[k] = $(id).checked; refresh(); };
  }
  $("#g-top").onchange = () => { state.gopts.top = Number($("#g-top").value) || 15; refresh(); };
  $("#g-layout").onchange = () => { state.layout = $("#g-layout").value; refresh(); };
  $("#connect").onclick = () => askToken().then((t) => { if (t) refresh(); });
  const sev = $("#anomaly-sev");
  if (sev) sev.onchange = () => refresh();
  const dg = $("#dest-group");
  if (dg) dg.onchange = () => refresh();
  const inc = $("#incident-status");
  if (inc) inc.onchange = () => refresh();
  $("#g-fit").onclick = () => diagram.fit();
  $("#g-svg").onclick = () => {
    const svg = $("#diagram svg");
    if (!svg) return;
    // The root carries the current pan/zoom transform; exporting it as-is
    // opens the diagram translated off-screen.
    const clone = svg.cloneNode(true);
    clone.removeAttribute("style");
    download(`netgraph-${fileStamp()}.svg`, clone.outerHTML, "image/svg+xml");
  };
  $("#g-d2").onclick = async () => {
    if (!state.graph) return;
    const script = engineState === "ready"
      ? (await engine.call("d2", { graph: state.graph, theme: theme() })).script
      : await api("graph", { ...graphOpts(), format: "d2" }, true);
    download(`netgraph-${fileStamp()}.d2`, script, "text/plain");
  };
  $("#ask-open").onclick = openAsk;
  $("#whatif-open").onclick = openWhatIf;
  $("#whatif-run").onclick = runWhatIf;
  $("#ask-form").onsubmit = async (e) => {
    e.preventDefault();
    const q = $("#ask-q").value.trim();
    if (!q) return;
    $("#ask-answer").innerHTML = `<p class="muted">Investigating…</p>`;
    try {
      const a = await send("POST", "ask", { q, from: String(state.to - state.span), to: String(state.to) });
      renderAnswer(a);
    } catch (err) {
      $("#ask-answer").innerHTML = `<p class="muted">${esc(err.message)}</p>`;
    }
  };
  $("#panel-close").onclick = closePanel;
  $("#theme").onclick = () => {
    const next = theme() === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    store.set("netgraph.theme", next)
    refresh();
  };
  document.addEventListener("keydown", (e) => {
    if (e.target.matches("input, select, textarea")) return;
    const k = e.key;
    if (k === "Escape") closePanel();
    else if (k === "[") $("#back").click();
    else if (k === "]") $("#fwd").click();
    else if (k === "l") $("#live").click();
    else if (k === "t") { e.preventDefault(); $("#recorder").click(); }
    else if (k === " ") { if (state.rec.on && !e.target.matches("button, a, input, select, textarea")) { e.preventDefault(); togglePlay(); } }
    else if (k === "/") { e.preventDefault(); $("#filter").focus(); }
    else if (k === "?") { e.preventDefault(); openAsk(); }
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
    renderWindow();
    for (const [id, k] of [["#g-collapse", "collapse"], ["#g-dns", "dns"], ["#g-sites", "sites"], ["#g-anomalies", "anomalies"], ["#g-networks", "networks"], ["#g-identity", "identity"]]) {
      $(id).checked = state.gopts[k];
    }
    $("#g-top").value = state.gopts.top;
    $("#g-layout").value = state.layout;
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
