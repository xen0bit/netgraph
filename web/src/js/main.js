// netgraph web UI. Everything comes straight from the JSON API; the map is
// drawn here, on a canvas (map/map.js).
import { LivingMap } from "./map/map.js";
import { reelFrame, reelDiff } from "./reel.js";
import { esc, units, parseSpan, fmtSpan, bytes, pad2, clock, stamp, ago } from "./util.js";
import { homeHTML, installBlock } from "./home.js";
import { parseWhen, fuzzy } from "./palette.js";
import { tokens, lastToken, localSuggestions, searched } from "./filters.js";
import { passportHTML } from "./passport.js";
import { Privacy } from "./privacy.js";
import { findingsHTML, findingDetail } from "./findings.js";
import { airspaceHTML } from "./airspace.js";
import { emptyPolicy, loadDraft, saveDraft, addEdge, policyHTML, impactHTML, readRule } from "./policy.js";
import { sensorStatus, sensorDetail, fleetSettingsHTML, readSettings } from "./fleet.js";
import { typeBadge, typeWhy, profileForm, presenceHTML, linksHTML, qualityHTML } from "./devices.js";
import { Pulse } from "./pulse.js";

const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];

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
  tab: "home",
  gopts: { collapse: true, dns: true, sites: true, anomalies: true, networks: true, identity: false, top: 15 },
  graph: null,
  data: {},
  // Per table: the column it is sorted by ({col, dir}), and how many rows
  // to ask for when "load more" raised the API's default.
  sort: {},
  limits: {},
  // The entity whose details are open, so a link can reopen them.
  open: "",
  // The device the Passport view shows.
  passport: "",
  // Flight Recorder: when on, the window ends at this moment and the event
  // rail shows what happened just before it.
  rec: { on: false, at: Date.now(), lookback: 5 * 60_000, follow: "", playing: false, diffA: 0, view: null, loop: null, diff: null },
};

// The areas of the app, and the views inside each. A view's name is what links
// carry, so links from before the areas existed keep working.
const areas = {
  home: { tabs: [["home", "Home"]] },
  map: { tabs: [["graph", "Map"]] },
  devices: { tabs: [["devices", "Devices"], ["presence", "Presence"], ["links", "To confirm"], ["passport", "Passport"]] },
  activity: { tabs: [["flows", "Connections"], ["destinations", "Destinations"], ["dns", "DNS"], ["facts", "Facts"], ["pulse", "Pulse"], ["quality", "Internet"]] },
  findings: { tabs: [["findings", "Inbox"], ["anomalies", "This window"], ["incidents", "Incidents"], ["insights", "Insights"], ["policy", "Policy"]], tools: `<button id="whatif-open" type="button" title="Test a proposed policy against observed traffic">What-if</button>` },
  wifi: { tabs: [["wifi", "Networks"], ["airspace", "Airspace"]] },
  settings: { tabs: [["settings", "General"], ["sensors", "Sensors"]] },
};
const areaOf = (t) => Object.keys(areas).find((a) => areas[a].tabs.some(([id]) => id === t));
// Views that answer about now rather than about the window: the time controls,
// the Recorder and the filter have nothing to say to them.
const plainTabs = new Set(["home", "settings", "sensors", "incidents", "pulse", "passport", "links", "findings"]);

function loadHash() {
  const raw = location.hash.slice(1);
  const p = new URLSearchParams(raw);
  const num = (k) => { const v = Number(p.get(k)); return Number.isFinite(v) ? v : null; };
  const to = num("to");
  if (to && to > 0) state.to = to;
  const span = num("span");
  if (span && span >= 10_000) state.span = span;
  if (p.get("from") && to) state.span = Math.max(10_000, state.to - Number(p.get("from")));
  state.live = p.get("live") === "1" || !p.has("to");
  state.filter = p.get("q") || "";
  // A bare address lands on Home. A link with a window and no view is from
  // when the map was the only landing page, and from saveHash, which leaves the
  // map out.
  state.tab = areaOf(p.get("tab")) ? p.get("tab") : raw ? "graph" : "home";
  for (const k of ["collapse", "dns", "sites", "anomalies", "networks", "identity"]) if (p.has(k)) state.gopts[k] = p.get(k) === "1";
  const top = num("top");
  if (top === -1 || (top && top >= 1)) state.gopts.top = Math.min(top, 1000);
  // sort=<table>.<column>.<asc|desc>
  state.sort = {};
  const [st, col, dir] = (p.get("sort") || "").split(".");
  if (tables[st] && tables[st].keys[Number(col)] && (dir === "asc" || dir === "desc")) state.sort[st] = { col: Number(col), dir };
  state.open = p.get("open") || "";
  state.passport = p.get("device") || "";
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
  const so = state.sort[state.tab];
  if (so) p.set("sort", `${state.tab}.${so.col}.${so.dir}`);
  if (state.open) p.set("open", state.open);
  if (state.tab === "passport" && state.passport) p.set("device", state.passport);
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
    // The server reads these through its device filter, so one device term applies.
    else if (["type", "owner", "group"].includes(k)) out.device = tok;
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
const privacy = new Privacy(store);

// api reads JSON. Its query is the window and filter on screen plus extra, or
// exactly extra when that is already a URLSearchParams.
async function api(path, extra = {}, raw = false) {
  let retried = false;
  const query = extra instanceof URLSearchParams ? extra : params(extra);
  if (privacy.on) for (const [k, v] of [...query]) query.set(k, privacy.restore(v));
  for (;;) {
    const headers = token ? { Authorization: `Bearer ${token}` } : {};
    const resp = await fetch(`/api/v1/${privacy.restorePath(path)}?${query}`, { headers });
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
    return raw ? resp.text() : privacy.walk(await resp.json());
  }
}

// send writes JSON (a JSON body makes a cross-site request need a CORS
// preflight, which the server never grants).
async function send(method, path, body) {
  let retried = false;
  for (;;) {
    const headers = { "Content-Type": "application/json" };
    if (token) headers.Authorization = `Bearer ${token}`;
    const resp = await fetch(`/api/v1/${privacy.restorePath(path)}`, { method, headers, body: privacy.restore(JSON.stringify(body)) });
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
    return ct.includes("application/json") ? privacy.walk(await resp.json()) : resp.text();
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
        closeLive();
        syncFeed();
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

// saveToken trades a token that worked for a session cookie scripts can't read, and
// then stops holding it. If that can't happen, it stays in this browser, as it used to.
let exchanging = null;
function saveToken() {
  $("#connect").hidden = true;
  if (!token || exchanging) return;
  const used = token;
  exchanging = fetch("/api/v1/session", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ token: used }) })
    .then((r) => {
      if (!r.ok) throw new Error(String(r.status));
      store.remove("netgraph.token");
      if (token === used) token = "";
      loadMe();
    })
    .catch(() => store.set("netgraph.token", used))
    .finally(() => { exchanging = null; });
}

// Who this page is talking as.
let me = null;
function loadMe() {
  return api("me", new URLSearchParams()).then((m) => {
    me = m;
    document.body.dataset.role = m.role;
    if (state.tab === "settings") renderSettings();
    return m;
  }).catch(() => null);
}
const can = (role) => { const order = { viewer: 1, operator: 2, admin: 3 }; return !me || order[me.role] >= order[role]; };

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
  document.body.classList.toggle("rec-on", state.rec.on);
  renderChips();
  const seq = ++refreshSeq;
  pollFindingCount();
  if (plainTabs.has(state.tab)) {
    await loadRange();
    if (seq === refreshSeq) await renderTab(seq);
    return;
  }
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
    reportSeq = seq;
    renderSummary(summary, report);
    if (state.tab === "graph" && state.graph) diagram.applyMarks((g) => markGraph(g, report));
  })();
  const spark = track(api("timeseries", { step })).catch(() => null).then((s) => { if (seq === refreshSeq) renderSpark(s); });
  // An empty view offers a way to the data, so it needs to know where that is.
  const view = loadRange().then(() => (seq === refreshSeq ? renderTab(seq) : null));
  await Promise.all([headline, spark, view, state.rec.on ? renderRail(seq) : null]);
  if (seq === refreshSeq) renderRecorder();
}

let lastReport = null;
let reportSeq = 0;

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

// --- Home -------------------------------------------------------------------------

// A visit is a session: the page counts as seen while someone keeps coming back
// within half an hour, and a longer gap starts a new "since you were last here"
// from where the last session ended.
const visitGap = 30 * units.m;
function visitSince() {
  const now = Date.now();
  let v = null;
  try { v = JSON.parse(store.get("netgraph.visit") || "null"); } catch { /* start over */ }
  if (!v || typeof v.beat !== "number") v = { since: 0, beat: now };
  else if (now - v.beat > visitGap) v = { since: v.beat, beat: now };
  else v.beat = now;
  store.set("netgraph.visit", JSON.stringify(v));
  return v.since;
}

let homeState = { at: 0, report: null, findings: null, firstVisit: false, links: 0 };
const homePoll = () => (homeState.report?.state === "no_data" ? 3000 : 30_000);

function drawHome() {
  const el = $("#home-body");
  if (!homeState.report) return;
  el.innerHTML = homeHTML(homeState.report, homeState.findings, { firstVisit: homeState.firstVisit, origin: location.origin, links: homeState.links });
}

// renderHome draws what it has, then the findings when their checks finish: they
// can take far longer, and the page must not wait for them. An ingest asks for
// this every couple of seconds, which the landing page does not need.
async function renderHome(seq, { force = false } = {}) {
  if (!force && homeState.report && Date.now() - homeState.at < homePoll()) { drawHome(); return; }
  homeState.at = Date.now();
  const since = visitSince();
  homeState.firstVisit = !since;
  const report = await track(api("home", new URLSearchParams(since ? { since } : {})));
  if (seq !== refreshSeq) return;
  const sameSince = homeState.report?.since === report.since;
  homeState.report = report;
  if (!sameSince) homeState.findings = null;
  drawHome();
  if (report.state === "no_data") return;
  track(api("devices/links", new URLSearchParams())).then((l) => {
    if (seq !== refreshSeq) return;
    homeState.links = l.length;
    drawHome();
  }).catch(() => {});
  // What's already been found, so the page doesn't wait for the checks to run.
  const findings = await track(api("findings", new URLSearchParams({ status: "open", since: report.since, limit: 200 }))).catch(() => null);
  if (seq !== refreshSeq || !findings) return;
  showFindingCount(findings.counts);
  homeState.findings = findings;
  drawHome();
}

function homeClick(e) {
  const seen = e.target.closest("[data-home-seen]");
  if (seen) {
    const now = Date.now();
    store.set("netgraph.visit", JSON.stringify({ since: now, beat: now }));
    homeState.findings = null;
    renderHome(refreshSeq, { force: true }).catch(() => {});
    return;
  }
  const jump = e.target.closest("[data-jump]");
  if (jump) {
    const ts = Number(jump.dataset.jump), step = Number(jump.dataset.step);
    if (state.live) setLive(false);
    state.to = ts + step;
    state.span = Math.max(step, units.h);
    selectTab("graph");
    return;
  }
  if (e.target.closest("[data-home-findings]")) { selectTab("findings"); return; }
  const open = e.target.closest("[data-open]");
  if (open) { openEntity(open.dataset.open); return; }
  const tab = e.target.closest("[data-tab]");
  if (tab) selectTab(tab.dataset.tab);
}

// --- findings -----------------------------------------------------------------------

let findingsStatus = "open";

// The count of unread findings, on the tab, whatever view is open.
function showFindingCount(counts) {
  const el = $("#findings-count");
  const n = counts?.new || 0;
  el.hidden = !n;
  el.textContent = n > 99 ? "99+" : String(n);
  el.title = `${n} new`;
}

async function renderFindings(seq) {
  const q = new URLSearchParams();
  if (findingsStatus) q.set("status", findingsStatus);
  const l = await track(api("findings", q));
  if (seq !== refreshSeq) return;
  showFindingCount(l.counts);
  $("#findings-body").innerHTML = findingsHTML(l, findingsStatus);
}

let lastFindingCount = 0;
function pollFindingCount() {
  if (Date.now() - lastFindingCount < 30_000) return;
  lastFindingCount = Date.now();
  api("findings", new URLSearchParams({ limit: 1 })).then((l) => showFindingCount(l.counts)).catch(() => {});
}

// A sensor's panel. Saving reads the list again: whether it's been picked up is the sensor's to say.
function sensorForm(path, redraw) {
  $("#panel-body").onsubmit = async (e) => {
    const form = e.target.closest("[data-fleet-form]");
    if (!form) return;
    e.preventDefault();
    const said = form.querySelector("[data-fleet-said]");
    try {
      await send("PUT", path, readSettings(form));
      said.textContent = "Saved. Sensors pick this up within a minute.";
      redraw?.();
    } catch (err) { said.textContent = err.message; }
  };
}

async function openFleetSettings() {
  $("#panel").hidden = false;
  ++entityReq;
  const values = await track(api("sensors/%2A/config", new URLSearchParams())).catch(() => ({}));
  $("#panel-body").innerHTML = fleetSettingsHTML(values);
  $("#panel-body").onclick = null;
  sensorForm("sensors/%2A/config");
}

function openSensor(s) {
  $("#panel").hidden = false;
  ++entityReq;
  state.open = `sensor:${s.name}`;
  $("#panel-body").innerHTML = sensorDetail(s);
  $("#panel-body").onclick = (e) => { if (e.target.closest("[data-fleet-all]")) openFleetSettings(); };
  sensorForm(`sensors/${encodeURIComponent(s.name)}/config`, () => refresh());
}

async function openFinding(id) {
  const panel = $("#panel");
  panel.hidden = false;
  const req = ++entityReq;
  let f;
  try {
    f = await track(api(`findings/${id}`, new URLSearchParams()));
  } catch (e) {
    if (req === entityReq) $("#panel-body").innerHTML = `<p class="muted">${esc(e.message)}</p>`;
    return;
  }
  if (req !== entityReq) return;
  $("#panel-body").innerHTML = findingDetail(f);
  const act = (p) => p.then(() => { lastFindingCount = 0; refresh(); openFinding(id); }).catch((e) => setStatus(e.message, true));
  $("#panel-body").onclick = (e) => {
    const st = e.target.closest("[data-fstatus]");
    if (st) { act(send("PATCH", `findings/${id}`, { status: st.dataset.fstatus })); return; }
    if (e.target.closest("[data-ffine]")) { act(send("POST", `findings/${id}/fine`, { note: "" })); return; }
    const dev = e.target.closest("[data-fdevice]");
    if (dev) { openPassport(dev.dataset.fdevice); return; }
    if (e.target.closest("[data-fmoment]")) {
      if (state.live) setLive(false);
      state.to = f.last_seen + units.m * 5;
      state.span = units.h;
      const narrow = [f.entity, f.device].find((x) => /^(ip|asn|device):/.test(x || ""));
      if (narrow) state.filter = narrow;
      closePanel();
      selectTab("graph");
    }
  };
  $("#panel-body form.finding-note").onsubmit = (e) => {
    e.preventDefault();
    act(send("PATCH", `findings/${id}`, { status: "", note: e.target.elements.note.value }));
  };
  if (f.status === "new") send("PATCH", `findings/${id}`, { status: "seen" }).then(() => { lastFindingCount = 0; pollFindingCount(); }).catch(() => {});
}

function findingsClick(e) {
  const st = e.target.closest("[data-findings-status]");
  if (st) { findingsStatus = st.dataset.findingsStatus; refresh(); return; }
  if (e.target.closest("[data-findings-seen]")) {
    send("POST", "findings/seen", {}).then(() => { lastFindingCount = 0; refresh(); }).catch((err) => setStatus(err.message, true));
    return;
  }
  const row = e.target.closest("[data-finding]");
  if (row) openFinding(Number(row.dataset.finding));
}

// --- passport -----------------------------------------------------------------------

function openPassport(id) {
  state.passport = id;
  closePanel();
  selectTab("passport");
}

async function renderPassport(seq) {
  const el = $("#passport-body");
  if (!state.passport) {
    el.innerHTML = `<div class="first-run"><h2>Passport</h2><p class="muted">A device's profile: who it is, when it's busy, and how this week compares. Pick one from Devices, the map or Find, then choose “Open its passport”.</p><button type="button" data-tab="devices">Devices →</button></div>`;
    return;
  }
  const p = await track(api("passport", new URLSearchParams({ id: state.passport, tz: -new Date().getTimezoneOffset() }))).catch((e) => {
    if (seq === refreshSeq) el.innerHTML = `<p class="muted empty">${esc(e.message)}</p>`;
    return null;
  });
  if (!p || seq !== refreshSeq) return;
  el.innerHTML = passportHTML(p);
}

function passportClick(e) {
  const tab = e.target.closest("[data-tab]");
  if (tab) { selectTab(tab.dataset.tab); return; }
  const id = state.passport;
  const other = e.target.closest("[data-pp-open]");
  if (other) { openPassport(other.dataset.ppOpen); return; }
  const unlink = e.target.closest("[data-pp-unlink]");
  if (unlink) {
    send("POST", `devices/${encodeURIComponent(unlink.dataset.ppUnlink)}/link`, { decision: "undo" })
      .then(() => { homeState.at = 0; refresh(); }).catch((err) => setStatus(err.message, true));
    return;
  }
  if (e.target.closest("[data-pp-details]")) { openEntity(id); return; }
  if (e.target.closest("[data-pp-map]")) { state.filter = `device:${id.slice("device:".length)}`; $("#filter").value = state.filter; selectTab("graph"); return; }
  if (e.target.closest("[data-pp-follow]")) { selectTab("graph"); follow(id); return; }
  const day = e.target.closest("[data-day]");
  if (day) {
    if (state.live) setLive(false);
    state.to = Number(day.dataset.day) + units.d;
    state.span = units.d;
    state.filter = `device:${id.slice("device:".length)}`;
    $("#filter").value = state.filter;
    selectTab("graph");
    return;
  }
  const copy = e.target.closest("[data-pp-copy]");
  if (copy) {
    navigator.clipboard.writeText(location.href).then(() => { copy.textContent = "Copied"; }, () => { copy.textContent = "Copy from the address bar"; });
    setTimeout(() => { copy.textContent = "Copy link"; }, 2000);
  }
}

// --- settings -----------------------------------------------------------------------

function renderSettings() {
  const r = dataRange;
  const t = store.get("netgraph.theme") || "";
  $("#settings-body").innerHTML = `<div class="settings">
    <section class="card"><h2>Appearance</h2>
      <div class="segmented" role="group" aria-label="Theme">
        ${[["", "Match the system"], ["light", "Light"], ["dark", "Dark"]].map(([v, l]) => `<button type="button" data-theme-set="${v}" aria-pressed="${t === v}">${l}</button>`).join("")}
      </div></section>
    <section class="card"><h2>Long-term archive</h2><div id="settings-archive" class="muted">Reading…</div></section>
    ${can("admin") && me ? `<section class="card"><h2>What's been changed</h2><div id="settings-audit" class="muted">Reading…</div></section>` : ""}
    <section class="card"><h2>Notifications</h2><div id="settings-notify" class="muted">Reading…</div></section>
    <section class="card"><h2>Saved views</h2>
      ${savedViews().length ? `<ul class="saved-list">${savedViews().map((v, i) => `<li><span><b>${esc(v.name)}</b> <span class="muted">${esc(v.tab)}${v.filter ? ` · ${esc(v.filter)}` : ""}</span></span> <button type="button" data-view-delete="${i}">Delete</button></li>`).join("")}</ul>` : `<p class="muted">None yet. “Save view” above any table or the map keeps its filter and window length, in this browser.</p>`}</section>
    <section class="card"><h2>Add a sensor</h2>${installBlock(location.origin)}</section>
    <section class="card"><h2>Privacy mode</h2>
      <p class="muted">For screenshots and demos: names and addresses become stand-ins, in this browser. Best effort, so check before you share. Exports that come straight from the server are turned off while it's on.</p>
      <button type="button" data-privacy-toggle>${privacy.on ? "Turn off privacy mode" : "Turn on privacy mode"}</button></section>
    <section class="card"><h2>You</h2>
      <p>${me ? `${me.user ? `<b>${esc(me.user)}</b>, a` : "A"} ${esc(me.role)}${{ proxy: ", as your login proxy says", token: ", with a token", session: ", signed in with a token", open: ": this server needs no sign-in" }[me.via] || ""}.` : "Reading…"}</p>
      <div class="actions"><button type="button" data-sign-out${me?.via === "session" || me?.via === "token" ? "" : " disabled"}>Sign out of this browser</button>
      <button type="button" data-forget-visit>Forget my last visit</button></div></section>
    <section class="card"><h2>What the server holds</h2>
      ${r?.last_ms ? `<dl class="facts-list"><dt>Oldest data</dt><dd>${esc(stamp(r.first_ms))}</dd><dt>Newest data</dt><dd>${esc(stamp(r.last_ms))}, ${esc(ago(Date.now() - r.last_ms))}</dd>
        <dt>Raw records since</dt><dd>${esc(stamp(r.raw_from_ms))}</dd><dt>Hourly totals since</dt><dd>${esc(stamp(r.rollup_from_ms))}</dd></dl>` : `<p class="muted">Nothing yet.</p>`}
      <p class="muted" id="settings-version"></p></section>
  </div>`;
  $("#settings-version").textContent = $("#version").textContent;
  api("archive", new URLSearchParams()).then((a) => {
    const el = $("#settings-archive");
    if (!el) return;
    const held = a.files ? `${a.files} ${a.files === 1 ? "file" : "files"}, ${bytes(a.bytes)}, from ${stamp(a.oldest).slice(0, 10)} to ${stamp(a.newest).slice(0, 10)}.` : "Nothing in it yet.";
    el.textContent = a.enabled ? `On. ${held} Read it with netgraph archive; the pages here don't show it.`
      : a.files ? `Off, with what was kept still there. ${held}` : "Off. With -archive-dir, what passes retention is kept in files instead of deleted.";
  }).catch(() => { const el = $("#settings-archive"); if (el) el.textContent = "Can't read it."; });
  if ($("#settings-audit")) {
    api("audit", new URLSearchParams({ limit: 50 })).then((rows) => {
      const el = $("#settings-audit");
      if (!el) return;
      el.innerHTML = rows.length
        ? `<table class="mini"><thead><tr><th>When</th><th>Who</th><th>What</th><th>On</th></tr></thead><tbody>${rows.map((a) => `<tr><td>${esc(stamp(a.ts))}</td><td>${esc(a.actor)}</td><td>${esc(a.action.replace("/api/v1/", ""))}</td><td class="mono">${esc(a.target)}</td></tr>`).join("")}</tbody></table>`
        : "Nothing yet.";
    }).catch(() => { const el = $("#settings-audit"); if (el) el.textContent = "Can't read it."; });
  }
  api("notify", new URLSearchParams()).then((n) => {
    const el = $("#settings-notify");
    if (!el) return;
    el.innerHTML = n.channels.length
      ? `<ul class="saved-list">${n.channels.map((c) => `<li><span><b>${esc(c.name)}</b> <span class="muted">${esc([c.min && `${c.min} and up`, c.kinds?.join(", "), c.quiet && `quiet ${c.quiet}`].filter(Boolean).join(" · "))}</span></span> <span><output class="muted"></output> <button type="button" data-notify-test="${esc(c.name)}">Send a test</button></span></li>`).join("")}</ul>`
      : `<p>None set up. Start the server with <code>-notify-file</code>, a file of channel URLs: <code>ntfy://</code>, <code>gotify://</code>, <code>telegram://</code>, <code>smtp://</code> or <code>https://</code>.</p>`;
  }).catch(() => { const el = $("#settings-notify"); if (el) el.textContent = "Can't read them."; });
}

// Turning it on or off reloads, from a clean address: what's on screen came through
// the old setting, and the address bar can hold real names.
function setPrivacy(on) {
  privacy.set(on);
  location.hash = on ? "tab=home" : "";
  location.reload();
}

function setTheme(t) {
  if (t) { document.documentElement.dataset.theme = t; store.set("netgraph.theme", t); }
  else { delete document.documentElement.dataset.theme; store.remove("netgraph.theme"); }
  diagram.setTheme(theme());
}

function settingsClick(e) {
  const test = e.target.closest("[data-notify-test]");
  if (test) {
    const out = test.parentElement.querySelector("output");
    out.textContent = "Sending…";
    send("POST", "notify/test", { name: test.dataset.notifyTest })
      .then((r) => { out.textContent = r.ok ? "Sent" : r.error; })
      .catch((err) => { out.textContent = err.message; });
    return;
  }
  if (e.target.closest("[data-privacy-toggle]")) { setPrivacy(!privacy.on); return; }
  const th = e.target.closest("[data-theme-set]");
  if (th) { setTheme(th.dataset.themeSet); renderSettings(); return; }
  if (e.target.closest("[data-sign-out]")) {
    token = "";
    store.remove("netgraph.token");
    fetch("/api/v1/session", { method: "DELETE", headers: { "Content-Type": "application/json" } }).finally(() => location.reload());
    return;
  }
  const del = e.target.closest("[data-view-delete]");
  if (del) { const v = savedViews(); v.splice(Number(del.dataset.viewDelete), 1); saveViews(v); renderSettings(); return; }
  if (e.target.closest("[data-forget-visit]")) { store.remove("netgraph.visit"); homeState = { at: 0, report: null, findings: null, firstVisit: false, links: 0 }; setStatus("Last visit forgotten"); }
}

// copyClick copies a command block, saying so on the button.
async function copyClick(e) {
  const b = e.target.closest("[data-copy]");
  if (!b) return;
  try {
    await navigator.clipboard.writeText(b.dataset.copy);
    b.textContent = "Copied";
  } catch { b.textContent = "Select it to copy"; }
  setTimeout(() => { b.textContent = "Copy"; }, 2000);
}

const tablePath = { devices: "devices", flows: "flows", destinations: "destinations", dns: "dns", facts: "facts", wifi: "wifi", sensors: "sensors", anomalies: "anomalies", incidents: "incidents" };

async function renderTab(seq) {
  const t = state.tab;
  try {
    if (t === "graph") return await renderGraph(seq);
    if (t === "home") return await renderHome(seq);
    if (t === "settings") return renderSettings();
    if (t === "passport") return await renderPassport(seq);
    if (t === "findings") return await renderFindings(seq);
    if (t === "policy") return await renderPolicy(seq);
    if (t === "airspace") {
      const a = await track(api("airspace"));
      if (seq === refreshSeq) $("#airspace-body").innerHTML = airspaceHTML(a);
      return;
    }
    if (t === "quality") {
      const q = await track(api("quality"));
      if (seq === refreshSeq) $("#quality-body").innerHTML = qualityHTML(q);
      return;
    }
    if (t === "presence") {
      const p = await track(api("presence"));
      if (seq === refreshSeq) $("#presence-body").innerHTML = presenceHTML(p);
      return;
    }
    if (t === "links") {
      const l = await track(api("devices/links", new URLSearchParams()));
      if (seq === refreshSeq) { homeState.links = l.length; $("#links-body").innerHTML = linksHTML(l); }
      return;
    }
    if (t === "pulse") return;
    if (t === "insights") return await renderInsights(seq);
    const path = tablePath[t];
    const extra = state.limits[t] ? { limit: state.limits[t] } : {};
    if (t === "destinations" && $("#dest-group")?.value) extra.group = $("#dest-group").value;
    if (t === "incidents" && $("#incident-status")?.value) extra.status = $("#incident-status").value;
    Object.assign(extra, serverSort(t));
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

let lastPrecision = "";
function renderSummary(s, rep) {
  const el = $("#summary");
  if (!s) { el.textContent = ""; return; }
  lastPrecision = s.precision;
  const as = rep?.anomalies || [];
  const top = ["high", "medium", "low"].find((sev) => as.some((a) => a.severity === sev));
  el.innerHTML = [
    as.length ? `<a class="badge sev-${top}" data-tab="anomalies" title="Most severe: ${esc(top)}">${as.length} ${as.length === 1 ? "anomaly" : "anomalies"}</a>`
      : rep?.learning ? `<span class="hour" title="Checks that compare with history start a day after the first sensor reported">learning the network</span>` : "",
    `<span><b>${s.devices}</b> devices</span>`,
    `<span title="Connections in the window; inbound ones were opened from outside to a device here"><b>${s.flows}</b> connections${s.inbound ? ` (<b>${s.inbound}</b> inbound)` : ""}${s.precision === "hour" ? "" : `, peak <b>${s.peak_connections}</b> open`}</span>`,
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
    cols: ["Device", "Type", "Vendor", "Addresses", "Hostnames · services", "Conns", "Lookups", "Sent", "Received", "Active"],
    titles: { 1: "What it probably is, from what it said about itself; open it for why", 5: "Connections; how many of them came in from outside", 7: "Bytes the device sent", 8: "Bytes the device received" },
    num: [5, 6, 7, 8],
    row: (d) => [
      `${esc(d.label)}${d.owner ? ` <span class="badge">${esc(d.owner)}</span>` : ""}${(d.groups || []).map((g) => ` <span class="badge">${esc(g)}</span>`).join("")}${d.user_label && d.auto_label ? `<div class="sub">${esc(d.auto_label)}</div>` : ""}<div class="sub mono">${esc(d.mac)}</div>`,
      typeBadge(d),
      esc(d.randomized ? "private MAC" : d.vendor_short || d.vendor || "") + (d.role ? " " + badge(d.role) : ""),
      `<span class="mono">${(d.ips || []).map(esc).join("<br>")}</span>`,
      (d.serves?.length ? `<span class="badge dir-in" title="Ports clients connected to">serves ${esc(d.serves.join(", "))}</span>` : "") +
        [...(d.hostnames || []), ...(d.services || [])].map((x) => badge(x)).join(""),
      d.flows + (d.inbound ? `<div class="sub">${d.inbound} in</div>` : ""), d.dns_queries, bytes(d.bytes_out), bytes(d.bytes_in),
      `${when(d.active_from)}–${when(d.active_to)}`,
    ],
    keys: [(d) => d.label, (d) => d.type, (d) => (d.randomized ? "private MAC" : d.vendor_short || d.vendor), (d) => addrKey(d.ips?.[0]),
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
    // The columns the server can sort before its limit.
    server: { 0: "first_seen", 8: "bytes_out", 9: "bytes_in", 10: "last_seen" },
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
        (f.state ? badge(f.state, f.state) : "") + (f.closed ? badge(f.truncated ? "truncated" : f.end_reason || "closed", "closed") : ""),
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
    cols: ["Sensor", "Status", "Version", "Interfaces", "First seen", "Last seen", "Packets", "Kernel drops", "Active flows", "Evicted", "Queued", "Sent", "Send errors"],
    num: [6, 7, 8, 9, 10, 11, 12],
    row: (s) => [esc(s.name), sensorStatus(s), esc(s.version), esc((s.interfaces || []).join(", ")), stamp(s.first_seen), stamp(s.last_seen),
      s.stats?.packets ?? "", s.stats?.kernel_drops ?? "", s.stats?.flows_active ?? "", s.stats?.flows_evicted ?? "",
      s.stats?.events_queued ?? "", s.stats?.batches_sent ?? "", s.stats?.send_errors ?? ""],
    keys: [(s) => s.name, (s) => s.status, (s) => s.version, (s) => (s.interfaces || []).join(" "), (s) => s.first_seen, (s) => s.last_seen,
      (s) => s.stats?.packets, (s) => s.stats?.kernel_drops, (s) => s.stats?.flows_active, (s) => s.stats?.flows_evicted,
      (s) => s.stats?.events_queued, (s) => s.stats?.batches_sent, (s) => s.stats?.send_errors],
    id: (s) => `sensor:${s.name}`,
    open: (s) => openSensor(s),
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
  // A capped table holds only the top of the old order: ask for the new one.
  const [def] = limits[t] || [];
  if (spec.server && def && (state.data[t]?.length || 0) >= (state.limits[t] || def)) {
    const was = state.sort[t];
    if (!was || spec.server[was.col] || spec.server[cur?.col]) { delete state.limits[t]; refresh(); return; }
  }
  renderTable(t);
}

// serverSort is the query asking the server for a table's sort, if it can. The
// server only reads it for exact answers; hourly ones are sorted here.
function serverSort(t) {
  const so = state.sort[t], col = so && tables[t]?.server?.[so.col];
  return col ? { sort: (so.dir === "desc" ? "-" : "") + col } : {};
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
    const add = await track(api(tablePath[t], { limit: next - asked, offset, ...serverSort(t) }));
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
  const hiddenCols = hiddenColumns(t);
  renderColumnPicker(t, tools, hiddenCols);
  const shown = (i) => !hiddenCols.has(i);
  const head = `<thead><tr>${spec.cols.map((c, i) => {
    if (!shown(i)) return "";
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
  const sortedThere = serverSort(t).sort && lastPrecision !== "hour";
  tools.querySelector(".count").textContent = `${all.length} ${all.length === 1 ? "row" : "rows"}` +
    (capped ? ` · the first ${asked}${so && !sortedThere ? "; sorting covers these only" : ""}` : "");
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
    if (b) { sortBy(t, Number(b.dataset.col)); return; }
    const tr = e.target.closest("tbody tr[data-i]");
    if (!tr) return;
    const r = rows[Number(tr.dataset.i)];
    const id = spec.id(r);
    if (!id) return;
    if (spec.open) spec.open(r);
    else openEntity(id);
  };
  tableScroll[t]?.disconnect();
  delete tableScroll[t];
  el.style.tableLayout = "";
  const span = spec.cols.filter((_, i) => shown(i)).length;
  if (!rows.length) {
    el.innerHTML = head + `<tbody><tr><td class="empty" colspan="${span}">Nothing in this window.${windowed(t) ? emptyAction() : ""}</td></tr></tbody>`;
    return;
  }
  const rowHTML = (r, i) => `<tr data-i="${i}">${spec.row(r).map((c, j) => (shown(j) ? `<td class="${spec.num?.includes(j) ? "num" : ""}">${c}</td>` : "")).join("")}</tr>`;
  if (rows.length <= chunkedFrom) {
    el.innerHTML = head + "<tbody>" + rows.map(rowHTML).join("") + "</tbody>";
    return;
  }
  renderChunks(t, el, head, rows, rowHTML, span);
}

// A long table draws only what is near the screen. Rows differ in height, so it
// goes by chunks: one that scrolls away keeps its measured height as an empty
// row, and a chunk not yet seen is given the first chunk's height. The columns
// are fixed from the first chunk so they don't shift as chunks come and go.
const chunkSize = 200;
const chunkedFrom = 400;
const tableScroll = {};
function renderChunks(t, el, head, rows, rowHTML, span) {
  const count = Math.ceil(rows.length / chunkSize);
  const fill = (k) => rows.slice(k * chunkSize, (k + 1) * chunkSize).map((r, i) => rowHTML(r, k * chunkSize + i)).join("");
  const blank = (px) => `<tr class="chunk-blank" style="height:${px}px"><td colspan="${span}"></td></tr>`;
  el.innerHTML = `${head}<tbody data-chunk="0">${fill(0)}</tbody>`;
  const first = el.querySelector("tbody");
  const each = first.getBoundingClientRect().height / first.rows.length || 30;
  // Fix the widths the first chunk asked for; a hidden view measures nothing.
  const ths = [...el.querySelectorAll("thead th")];
  const widths = ths.map((th) => th.getBoundingClientRect().width);
  if (widths.every((w) => w > 0)) {
    ths.forEach((th, i) => { th.style.width = `${widths[i]}px`; });
    el.style.tableLayout = "fixed";
  }
  let html = "";
  for (let k = 1; k < count; k++) {
    const n = Math.min(chunkSize, rows.length - k * chunkSize);
    html += `<tbody data-chunk="${k}">${blank(Math.round(n * each))}</tbody>`;
  }
  first.insertAdjacentHTML("afterend", html);
  const seen = new IntersectionObserver((entries) => {
    for (const e of entries) {
      const body = e.target, k = Number(body.dataset.chunk);
      const empty = body.rows[0]?.classList.contains("chunk-blank");
      if (e.isIntersecting && empty) body.innerHTML = fill(k);
      else if (!e.isIntersecting && !empty) body.innerHTML = blank(Math.round(body.getBoundingClientRect().height));
    }
  }, { root: el.closest(".view"), rootMargin: "1200px 0px" });
  for (const body of el.querySelectorAll("tbody")) seen.observe(body);
  tableScroll[t] = seen;
}

// Which columns are turned off, per table, in this browser.
function hiddenColumns(t) {
  try { return new Set(JSON.parse(store.get(`netgraph.cols.${t}`) || "[]")); } catch { return new Set(); }
}

function renderColumnPicker(t, tools, hidden) {
  const box = tools.querySelector(".columns ul");
  box.innerHTML = tables[t].cols.map((c, i) => (c
    ? `<li><label><input type="checkbox" data-col="${i}"${hidden.has(i) ? "" : " checked"}> ${esc(c)}</label></li>` : "")).join("");
  box.onchange = (e) => {
    const i = Number(e.target.dataset.col);
    const now = hiddenColumns(t);
    if (e.target.checked) now.delete(i); else now.add(i);
    store.set(`netgraph.cols.${t}`, JSON.stringify([...now]));
    renderTable(t);
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
      <details class="columns"><summary>Columns</summary><ul></ul></details>
      <button data-copy-json title="Copy these rows as JSON">Copy JSON</button>
      <button data-export title="Download every row in this window, every field, as CSV">All CSV</button>
      <button data-csv title="Download these rows, every field, as CSV">CSV</button>`;
    table.before(tools);
  }
  return tools;
}

// --- graph ----------------------------------------------------------------------

const pulse = new Pulse($("#pulse-list"), {
  onOpen: (id) => openEntity(id),
  onCount: (p) => {
    $("#pulse-empty").hidden = p.lines > 0;
    $("#pulse-count").textContent = [
      `${p.lines} ${p.lines === 1 ? "line" : "lines"}`,
      p.held.length ? `${p.held.length} waiting` : "",
      p.dropped ? `${p.dropped} too many to show` : "",
    ].filter(Boolean).join(" · ");
  },
});

const diagram = new LivingMap($("#diagram"), {
  onSelect: (id) => openEntity(id),
  onEdge: (e) => openEdge(e),
  onExpand: (id) => toggleExpand(id),
  onMenu: (target, x, y) => openMapMenu(target, x, y),
  onPin: (id, x, y) => send("PUT", "map/pins", { pins: [{ id, x, y }] }).catch((e) => setStatus(e.message, true)),
  onSelection: (ids) => renderSelection(ids),
});

function theme() {
  const t = document.documentElement.dataset.theme;
  if (t) return t;
  return matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function graphOpts() {
  const b = (k) => (state.gopts[k] ? "1" : "0");
  return { collapse: b("collapse"), dns: b("dns"), sites: b("sites"), anomalies: b("anomalies"), networks: b("networks"), identity: b("identity"), top: String(state.gopts.top) };
}

// Nodes opened in place on the map: a device's "N more", or a site's names.
const expanded = new Set();

// expansionQueries says what to ask for to open a node in place.
function expansionQueries(id) {
  const b = (k) => ({ top: "-1", anomalies: "0", ...k });
  if (id.startsWith("other:")) {
    const clients = id.startsWith("other:clients:");
    const dev = id.slice(clients ? "other:clients:".length : "other:".length);
    const [kind, ...rest] = dev.split(":");
    const key = rest.join(":");
    const who = kind === "device" ? { device: key } : { ip: key };
    return [b({ ...who, dir: clients ? "in" : "out" })];
  }
  if (id.startsWith("site:")) {
    const key = id.slice("site:".length);
    return [b({ domain: key, sites: "0" }), b({ domain: `*.${key}`, sites: "0" })];
  }
  return null;
}

// mergeExpansion replaces a node with what it stands for.
function mergeExpansion(g, id, parts) {
  const nodes = new Map(g.nodes.filter((n) => n.id !== id).map((n) => [n.id, n]));
  const edge = (e) => `${e.from}\u0000${e.to}\u0000${e.rel}`;
  const edges = new Map(g.edges.filter((e) => e.from !== id && e.to !== id).map((e) => [edge(e), e]));
  let added = 0;
  for (const p of parts) {
    for (const n of p.nodes || []) {
      if (nodes.has(n.id)) continue;
      nodes.set(n.id, { ...n, attrs: { ...n.attrs, expanded_from: id } });
      added++;
    }
    for (const e of p.edges || []) if (!edges.has(edge(e))) edges.set(edge(e), e);
  }
  // Asking again for the same device can bring back another "N more" for it.
  for (const k of [...nodes.keys()]) if (k === id) nodes.delete(k);
  return { ...g, nodes: [...nodes.values()], edges: [...edges.values()].filter((e) => nodes.has(e.from) && nodes.has(e.to)), added };
}

async function withExpansions(g) {
  for (const id of expanded) {
    if (!g.nodes?.some((n) => n.id === id)) continue;
    const parts = await Promise.all(expansionQueries(id).map((q) => api("graph", { ...graphOpts(), ...q })));
    g = mergeExpansion(g, id, parts);
  }
  return g;
}

function toggleExpand(id) {
  if (state.rec.on) { setStatus("Leave the Recorder to open nodes in place"); return; }
  const node = state.graph?.nodes?.find((n) => n.id === id);
  const from = node?.attrs?.expanded_from;
  if (from) expanded.delete(from);
  else if (expansionQueries(id)) expanded.add(id);
  else return;
  refresh();
}

// markGraph outlines what medium and high anomalies are about, on a graph
// already drawn (graph.MarkAnomalies, which the server's own renderers use).
// A site's names are the names under it: its registrable domain is the suffix.
function markGraph(g, report) {
  for (const n of g.nodes || []) { if (n.attrs) { delete n.attrs.anomaly; delete n.attrs.anomalies; } }
  for (const e of g.edges || []) { if (e.attrs) { delete e.attrs.anomaly; delete e.attrs.anomalies; } }
  if (!state.gopts.anomalies) return;
  const rank = { low: 1, medium: 2, high: 3 };
  const mark = (x, a) => {
    x.attrs ??= {};
    if ((rank[a.severity] || 0) > (rank[x.attrs.anomaly] || 0)) x.attrs.anomaly = a.severity;
    const lines = (x.attrs.anomalies || "").split("\n");
    if (!lines.includes(a.summary)) x.attrs.anomalies = [...lines.filter(Boolean), a.summary].join("\n");
  };
  const about = (n, id) => {
    if (n.id === id) return true;
    const i = id.indexOf(":");
    const kind = id.slice(0, i), key = id.slice(i + 1);
    if (kind === "site") {
      if (n.kind === "domain") return n.label === key || n.label.endsWith(`.${key}`);
      return n.kind === "site" && n.id === id;
    }
    if (kind === "ip" && ["domain", "site", "asn"].includes(n.kind)) return (n.attrs?.addresses || "").split(",").includes(key);
    return false;
  };
  const byId = new Map((g.nodes || []).map((n) => [n.id, n]));
  for (const a of report?.anomalies || []) {
    if ((rank[a.severity] || 0) < rank.medium) continue;
    const dev = byId.get(a.device);
    if (dev) mark(dev, a);
    const targets = new Set();
    if (a.entity) for (const n of g.nodes || []) if (about(n, a.entity)) { mark(n, a); targets.add(n.id); }
    for (const e of g.edges || []) {
      if ((e.from === a.device && targets.has(e.to)) || (e.to === a.device && targets.has(e.from))) mark(e, a);
    }
  }
}

let lastView = null;
let pinsLoaded = false;
async function renderGraph(seq) {
  const note = $("#graph-note");
  diagram.setTheme(theme());
  diagram.loading("Loading map…");
  // What is being graphed, apart from Live moving the window forward: a redraw
  // of the same view keeps the person's pan and zoom. Stepping or playing the
  // Recorder is the same view at another moment.
  const moment = state.live ? state.span : state.rec.on ? ["recorder", state.rec.follow] : [state.to, state.span];
  const view = JSON.stringify([graphOpts(), state.filter, moment]);
  let g;
  // A reel is drawn and redrawn only when it is a different reel: the head
  // moving is not a new graph. Its frame still needs showing.
  if (state.rec.on && reel && diagram.graphSource === reel && reelKey === JSON.stringify([recView(), { ...graphOpts(), anomalies: "0" }, state.filter, state.rec.follow])) {
    diagram.done();
    drawFrame();
    return;
  }
  try {
    if (!pinsLoaded) {
      const pins = await track(api("map/pins"));
      pinsLoaded = true;
      diagram.setPins(pins || []);
    }
    // Anomalies are outlined when their report arrives: their checks can take
    // far longer than the graph, which must not wait for them. The Recorder
    // draws its graph from the reel, the same for every moment in it.
    g = state.rec.on ? (await loadReel()).graph : await track(api("graph", { ...graphOpts(), anomalies: "0" }).then(withExpansions));
  } catch (e) {
    if (seq === refreshSeq) diagram.message(esc(e.message));
    return;
  }
  if (seq !== refreshSeq) return;
  state.graph = g;
  diagram.graphSource = state.rec.on ? reel : null;
  if (state.live || reportSeq === seq) markGraph(g, lastReport);
  if (!g.nodes?.length) {
    diagram.message(`No activity in this window.${emptyAction()}`);
  } else {
    diagram.show(g, { keepView: view === lastView, spanMS: state.span });
    if (state.rec.on) drawFrame();
    else if (diagram.frame) diagram.applyFrame(null);
  }
  lastView = view;
  const hidden = diagram.hiddenCount();
  note.textContent = `${g.nodes?.length || 0} nodes · ${g.edges?.length || 0} edges` +
    (g.truncated ? ` · showing each device's top ${state.gopts.top} destinations and clients` : "") +
    (g.precision === "hour" ? " · hourly precision" : "") +
    (hidden ? ` · ${hidden} hidden` : "");
  $("#g-unhide").hidden = !hidden;
}

// --- on the map --------------------------------------------------------------------

// A filter for one thing on the map, as the filter box's grammar writes it.
function filterTerm(id) {
  const i = id.indexOf(":");
  const kind = id.slice(0, i), key = id.slice(i + 1);
  if (kind === "device") return `device:${key}`;
  if (kind === "domain") return `domain:${key}`;
  if (kind === "site") return `domain:*${key}`;
  if (kind === "ip") return `ip:${key}`;
  if (kind === "asn") return `asn:${key}`;
  return "";
}

const applyFilter = (f) => { applyFilterText(f); };

function openEdge(e) {
  const panel = $("#panel");
  panel.hidden = false;
  const name = (id) => state.graph?.nodes?.find((n) => n.id === id)?.label || id;
  const filter = [filterTerm(e.from), filterTerm(e.to)].filter(Boolean).join(" ");
  const body = $("#panel-body");
  const stats = [
    e.ports?.length ? e.ports.join(", ") : "",
    e.bytes_out || e.bytes_in ? `up ${bytes(e.bytes_out)} · down ${bytes(e.bytes_in)}` : "",
    e.count ? `${e.count} ${e.rel === "connects" ? "connections" : "times"}${e.peak ? `, peak ${e.peak} open` : ""}` : "",
  ].filter(Boolean).map((s) => `<div class="muted">${esc(s)}</div>`).join("");
  body.innerHTML = `<h2>${esc(name(e.from))} → ${esc(name(e.to))}</h2>${stats}
    <p><a data-filter="${esc(filter)}">Filter the window to these</a>${e.rel === "connects" ? ` · <a data-whatif="1">What if this were blocked?</a> · In the policy: <a data-policy="allow">Allow</a> or <a data-policy="deny">Deny</a>` : ""}</p>
    <div id="edge-rows"><p class="muted">Loading…</p></div>`;
  body.onclick = (ev) => {
    const a = ev.target.closest("a");
    if (!a) return;
    if (a.dataset.id) openEntity(a.dataset.id);
    if (a.dataset.filter) applyFilter(a.dataset.filter);
    if (a.dataset.whatif) openWhatIf(blockPolicy(e));
    if (a.dataset.policy) addEdgeToPolicy(e, a.dataset.policy);
  };
  const q = {};
  for (const id of [e.from, e.to]) {
    const t = filterTerm(id);
    if (!t) continue;
    const i = t.indexOf(":");
    q[t.slice(0, i)] = t.slice(i + 1);
  }
  const box = $("#edge-rows");
  if (e.rel === "connects") {
    track(api("flows", { ...q, limit: 200 })).then((rows) => {
      const link = (id, label) => `<a data-id="${esc(id)}">${esc(label)}</a>`;
      box.innerHTML = rows?.length ? `<h3>Connections</h3><ul>${rows.map((f) => {
        const [client, server] = ends(f);
        return `<li><time>${when(f.first_seen)}</time>${dirBadge(f.direction)} ${client} → ${server} ${f.name ? link(peerID(f), f.name) : ""} ${f.state ? badge(f.state, f.state) : ""}${f.closed ? badge(f.end_reason, "closed") : ""} <span class="muted">sent ${bytes(f.bytes_out)} · received ${bytes(f.bytes_in)}</span></li>`;
      }).join("")}</ul>` : `<p class="muted">No connections found for this edge.</p>`;
    }).catch((err) => { box.innerHTML = `<p class="muted">${esc(err.message)}</p>`; });
  } else if (e.rel === "queried") {
    track(api("dns", { ...q, limit: 200 })).then((rows) => {
      box.innerHTML = rows?.length ? `<h3>Lookups</h3><ul>${rows.map((d) => `<li><time>${when(d.ts)}</time>${esc(d.qname)} <span class="muted">${esc(d.qtype)} ${esc(d.rcode)}</span></li>`).join("")}</ul>` : `<p class="muted">No lookups found for this edge.</p>`;
    }).catch((err) => { box.innerHTML = `<p class="muted">${esc(err.message)}</p>`; });
  } else {
    const attrs = Object.entries(e.attrs || {}).map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("");
    box.innerHTML = attrs ? `<dl>${attrs}</dl>` : "";
  }
}

// blockPolicy is a what-if starting point: everything as it is, except this.
function blockPolicy(e) {
  const selector = (id) => {
    const i = id.indexOf(":");
    const kind = id.slice(0, i), key = id.slice(i + 1);
    return ["site", "domain", "ip", "asn"].includes(kind) ? `${kind}:${key}` : "any";
  };
  const device = [e.from, e.to].find((id) => id.startsWith("device:"));
  const other = device === e.from ? e.to : e.from;
  const inbound = device === e.to;
  return {
    version: 1,
    zones: device ? [{ name: "this", devices: [device] }] : [],
    defaults: { egress: "allow", ingress: "allow", intra_zone: "allow", dns: "allow" },
    rules: [{
      name: "block this",
      from: inbound ? selector(other) : device ? "zone:this" : selector(e.from),
      to: inbound ? "zone:this" : selector(other),
      ports: e.ports || [],
      action: "deny",
    }],
    dns: { block: [], allow: [] },
  };
}

function closeMapMenu() { $("#map-menu")?.remove(); }

function openMapMenu(target, x, y) {
  closeMapMenu();
  const items = [];
  const n = target.node, e = target.edge;
  if (n) {
    const term = filterTerm(n.id);
    items.push(["Details", () => openEntity(n.id)]);
    if (n.kind === "device") items.push(["Rename…", () => openEntity(n.id).then(() => $("#panel-body form.rename input")?.focus())]);
    if (term) items.push([`Filter to this ${n.kind}`, () => applyFilter(term)]);
    if (["device", "domain", "site", "ip", "asn"].includes(n.kind)) items.push(["Follow in Recorder", () => follow(n.id)]);
    items.push(["Add a note…", () => openNote(n.id)]);
    if (expansionQueries(n.id)) items.push([n.id.startsWith("site:") ? "Open into its names" : "Show all of them here", () => toggleExpand(n.id)]);
    if (n.attrs?.expanded_from) items.push(["Close back up", () => toggleExpand(n.id)]);
    items.push(target.pinned
      ? ["Unpin", () => unpin([n.id])]
      : ["Hide from the map", () => hideNodes([n.id])]);
    const findings = (lastReport?.anomalies || []).filter((a) => a.device === n.id || a.entity === n.id);
    for (const a of findings.slice(0, 3)) {
      items.push([`Mute “${a.kind.replaceAll("_", " ")}” for 1 hour`, () => muteFinding(a)]);
    }
  } else if (e) {
    items.push(["Show its connections", () => openEdge(e)]);
    const f = [filterTerm(e.from), filterTerm(e.to)].filter(Boolean).join(" ");
    if (f) items.push(["Filter to these", () => applyFilter(f)]);
    if (e.rel === "connects") {
      items.push(["What if this were blocked?", () => openWhatIf(blockPolicy(e))]);
      items.push(["Allow in the policy", () => addEdgeToPolicy(e, "allow")], ["Deny in the policy", () => addEdgeToPolicy(e, "deny")]);
    }
  } else {
    items.push(["Fit to view", () => diagram.fit()], ["Re-arrange", () => diagram.rearrange()]);
  }
  const menu = document.createElement("div");
  menu.id = "map-menu";
  menu.className = "map-menu";
  menu.setAttribute("role", "menu");
  for (const [label, run] of items) {
    const b = document.createElement("button");
    b.type = "button";
    b.setAttribute("role", "menuitem");
    b.textContent = label;
    b.onclick = () => { closeMapMenu(); run(); };
    menu.append(b);
  }
  document.body.append(menu);
  const r = menu.getBoundingClientRect();
  menu.style.left = `${Math.min(x, innerWidth - r.width - 6)}px`;
  menu.style.top = `${Math.min(y, innerHeight - r.height - 6)}px`;
  menu.querySelector("button")?.focus();
  menu.onkeydown = (ev) => {
    const bs = [...menu.querySelectorAll("button")];
    const i = bs.indexOf(document.activeElement);
    if (ev.key === "ArrowDown") { ev.preventDefault(); bs[(i + 1) % bs.length].focus(); }
    else if (ev.key === "ArrowUp") { ev.preventDefault(); bs[(i - 1 + bs.length) % bs.length].focus(); }
    else if (ev.key === "Escape") { ev.stopPropagation(); closeMapMenu(); diagram.canvas.focus(); }
  };
}

async function muteFinding(a) {
  try {
    await send("POST", "anomalies/mute", { kind: a.kind, device: a.device || "", entity: a.entity || "", until: Date.now() + 3600_000, note: "muted from the map" });
    setStatus("muted for 1 hour");
    refresh();
  } catch (err) {
    setStatus(err.message, true);
  }
}

function hideNodes(ids) {
  diagram.hide(ids);
  diagram.selected.clear();
  renderSelection([]);
  refresh();
}

async function unpin(ids) {
  try {
    await send("DELETE", "map/pins", { ids });
    pinsLoaded = false;
    for (const id of ids) {
      diagram.pins.delete(id);
      const d = diagram.nodes.get(id);
      if (d) d.pinned = false;
    }
    diagram.wake();
  } catch (err) {
    setStatus(err.message, true);
  }
}

function renderSelection(ids) {
  const bar = $("#map-selection");
  bar.hidden = !ids.length;
  $("#map-selection-count").textContent = `${ids.length} selected`;
  $("#map-selection-hide").onclick = () => hideNodes(ids);
  $("#map-selection-unpin").onclick = () => unpin(ids);
  $("#map-selection-clear").onclick = () => { diagram.selected.clear(); diagram.wake(); renderSelection([]); };
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
  const hiddenAttrs = new Set(["user_label", "auto_label", "user_type", "owner", "groups", "same_as", "not_same_as", "link_copied"]);
  const attrs = Object.entries(d.attrs || {}).filter(([k]) => !hiddenAttrs.has(k))
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
    <dt>type</dt><dd>${typeBadge(dev)}</dd>
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
    return `<li><time>${when(f.first_seen)}</time>${dirBadge(f.direction)} ${line} ${f.state ? badge(f.state, f.state) : ""}${f.closed ? badge(f.end_reason, "closed") : ""} <span class="muted">sent ${bytes(f.bytes_out)} · received ${bytes(f.bytes_in)}</span></li>`;
  }).join("");
  const timeline = (d.timeline || []).slice(-300).map((e) => `<li><time>${when(e.ts)}</time>${badge(e.type)} ${esc(e.detail)}</li>`).join("");
  const flagged = anomaly
    ? [anomaly.summary, ...Object.entries(anomaly.evidence || {}).map(([k, v]) => `${k}: ${v}`)]
    : state.graph?.nodes?.find((n) => n.id === id)?.attrs?.anomalies?.split("\n");
  const anomalyBox = flagged ? `<div class="anomaly-box"><b>${anomaly ? `${esc(anomaly.severity)} ${esc(anomaly.kind.replaceAll("_", " "))}` : "Anomalies"}</b><ul>${flagged.map((l) => `<li>${esc(l)}</li>`).join("")}</ul>${anomaly ? `<button type="button" id="autopsy-anomaly">Autopsy</button> <button type="button" id="save-incident">Save incident</button> <button type="button" id="mute-anomaly">Mute this for 1 hour</button>` : ""}</div>` : "";
  $("#panel-body").innerHTML = `${anomalyBox}
    <h2>${esc(d.label || d.key)}</h2>
    <div class="muted mono">${esc(d.id)}</div>${d.kind === "device" ? `<p><a data-passport="${esc(d.id)}">Open its passport →</a></p>` : ""}${rename}${d.kind === "device" ? profileForm(dev, d.attrs) : ""}
    <dl><dt>first seen</dt><dd>${stamp(d.first_seen)}</dd><dt>last seen</dt><dd>${stamp(d.last_seen)}</dd>${devInfo}${attrs}</dl>
    ${dev ? `<details class="why-box"><summary>Why this type</summary>${typeWhy(dev)}</details>` : ""}
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
    <p><a data-expand="${esc(id)}">Show all of them here</a> (or double-click the node)</p>
    <p><a data-id="${esc(dev)}">Details of ${esc(name)}</a></p>
    <p><a data-filter="${esc(devFilter + (clients ? " dir:in" : " dir:out"))}">Filter the window to these ${what}</a>, or raise Top N.</p>`;
  $("#panel-body").onclick = (e) => {
    const a = e.target.closest("a");
    if (!a) return;
    if (a.dataset.expand) toggleExpand(a.dataset.expand);
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

// syncFeed keeps the event stream open while Live or the Pulse needs it.
function syncFeed() {
  const want = state.live || state.tab === "pulse";
  if (want && !liveFeed) openLive();
  else if (!want) closeLive();
}

function feedPulse(frame) {
  const data = /^data: (.*)$/m.exec(frame);
  if (!data) return;
  try { pulse.add(privacy.walk(JSON.parse(data[1]))); } catch { /* a frame it can't read costs that frame */ }
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
          const frame = buf.slice(0, i);
          if (/^event: ingest$/m.test(frame)) {
            if (state.live) onIngest();
            if (state.tab === "pulse") feedPulse(frame);
          }
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
    leaveRecorder();
    $("#recorder-bar").hidden = true;
    $("#event-rail").hidden = true;
    $("#recorder").setAttribute("aria-pressed", "false");
  }
  closeLive();
  clearInterval(liveTimer);
  clearTimeout(pending);
  pending = null;
  syncFeed();
  if (!on) {
    // The window stays where Live left it: nothing to fetch again.
    saveHash();
    renderWindow();
    return;
  }
  liveTimer = setInterval(refresh, 30_000);
  refresh();
}

// --- notes and bookmarks --------------------------------------------------------------

function openNote(entity = "") {
  const dlg = $("#note-dialog");
  $("#note-text").value = "";
  $("#note-entity").value = entity || state.rec.follow || state.open || "";
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

function openWhatIf(policy = whatifExample) {
  const dlg = $("#whatif-dialog");
  $("#whatif-policy").value = JSON.stringify(policy, null, 2);
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
    box.innerHTML = impactHTML(r);
  } catch (e) {
    status.textContent = e.message;
  }
}

// --- policy --------------------------------------------------------------------------

let policyDraft = null;
const draft = () => (policyDraft ??= loadDraft(store));
const windowBody = () => ({ from: String(state.to - state.span), to: String(state.to) });

// An edge's two ends have names on the map; the rule's name says them.
async function addEdgeToPolicy(e, action) {
  const name = (id) => state.graph?.nodes?.find((n) => n.id === id)?.label || id;
  if (!addEdge(draft(), e, action, name)) {
    setStatus(`A rule can't name ${name(e.from)} or ${name(e.to)}: open Findings, Policy to write one by hand.`, true);
    return;
  }
  saveDraft(store, draft());
  try {
    const r = await send("POST", "whatif", { policy: draft(), ...windowBody() });
    const s = r.summary || {};
    setStatus(`${action === "deny" ? "Denied" : "Allowed"} in the policy: it would stop ${s.blocked || 0} connections here, ${s.essential || 0} essential. See Findings, Policy.`);
  } catch (err) { setStatus(err.message, true); }
  if (state.tab === "policy") refresh();
}

let policyRun = 0;
async function simulatePolicy() {
  const box = $("#policy-impact");
  if (!box) return;
  const run = ++policyRun;
  box.textContent = "Working it out…";
  try {
    const r = await send("POST", "whatif", { policy: draft(), ...windowBody() });
    if (run === policyRun) box.innerHTML = impactHTML(r);
  } catch (err) {
    // A half-typed rule is the usual cause: say what's wrong, and wait for the next edit.
    if (run === policyRun) box.textContent = err.message;
  }
}

function policyChanged({ redraw = false } = {}) {
  saveDraft(store, draft());
  if (!redraw) policyDrawn = JSON.stringify(draft());
  $("#policy-config").hidden = true;
  $("#policy-warnings").innerHTML = "";
  $("[data-policy-download]").hidden = true;
  if (redraw) drawPolicy(policyDevices);
  else simulatePolicy();
}

let policyDevices = [];
let policyDrawn = "";
function drawPolicy(devices) {
  $("#policy-body").innerHTML = policyHTML(draft(), devices);
  policyDrawn = JSON.stringify(draft());
  simulatePolicy();
}

// A refresh, or Live ticking, mustn't redraw under someone typing or wipe an export. If the
// draft is what's on screen, only the simulation needs doing again.
async function renderPolicy(seq) {
  if (policyDrawn === JSON.stringify(draft()) && $("#policy-body").firstChild) {
    simulatePolicy();
    return;
  }
  const devices = await track(api("devices"));
  if (seq !== refreshSeq) return;
  policyDevices = devices;
  drawPolicy(devices);
}

function wirePolicy() {
  const body = $("#policy-body");
  body.addEventListener("change", (e) => {
    const p = draft();
    const tr = e.target.closest("tr[data-rule]");
    if (tr) { p.rules[Number(tr.dataset.rule)] = readRule(tr); policyChanged(); return; }
    const key = e.target.dataset.p;
    if (key && key in p.defaults) { p.defaults[key] = e.target.value; policyChanged(); }
  });
  body.addEventListener("click", async (e) => {
    const p = draft();
    const tr = e.target.closest("tr[data-rule]");
    const i = tr ? Number(tr.dataset.rule) : -1;
    const swap = (a, b) => { [p.rules[a], p.rules[b]] = [p.rules[b], p.rules[a]]; policyChanged({ redraw: true }); };
    if (e.target.closest("[data-rule-del]")) { p.rules.splice(i, 1); policyChanged({ redraw: true }); return; }
    if (e.target.closest("[data-rule-up]")) { swap(i, i - 1); return; }
    if (e.target.closest("[data-rule-down]")) { swap(i, i + 1); return; }
    if (e.target.closest("[data-rule-add]")) {
      p.rules.push({ name: "new rule", from: "any", to: "any", ports: [], action: "deny" });
      policyChanged({ redraw: true });
      return;
    }
    if (e.target.closest("[data-policy-clear]")) {
      policyDraft = emptyPolicy();
      policyChanged({ redraw: true });
      return;
    }
    if (e.target.closest("[data-policy-export]")) {
      const warnings = $("#policy-warnings"), out = $("#policy-config");
      warnings.textContent = "Writing it…";
      try {
        const x = await send("POST", "policy/export", { policy: p, format: $('[data-p="format"]').value, ...windowBody() });
        warnings.innerHTML = (x.warnings || []).map((w) => `<p class="${/NOT DENIED|MISSING/.test(w) ? "err" : "muted"}">${esc(w)}</p>`).join("");
        out.value = x.config;
        out.hidden = false;
        const dl = $("[data-policy-download]");
        dl.hidden = false;
        dl.onclick = () => download(x.filename, x.config, "text/plain");
      } catch (err) { warnings.textContent = err.message; }
    }
  });
  body.addEventListener("submit", async (e) => {
    if (e.target.id !== "policy-learn") return;
    e.preventDefault();
    const device = new FormData(e.target).get("device");
    const gaps = $("#policy-gaps");
    gaps.textContent = "Reading what it did…";
    try {
      const l = await track(api("policy/learn", new URLSearchParams({ device })));
      policyDraft = { ...emptyPolicy(), ...l.policy };
      policyChanged({ redraw: true });
      $("#policy-gaps").innerHTML = `<p>From ${l.connections} connections: ${l.policy.rules.length} rules.</p>${(l.gaps || []).map((g) => `<p class="muted">${esc(g)}</p>`).join("")}`;
    } catch (err) { gaps.textContent = err.message; }
  });
}

// --- ask -----------------------------------------------------------------------------

// askMap is a small map of what an answer's about, made the first time it's needed.
let askMap = null;
async function drawAskMap(a) {
  const el = $("#ask-map");
  el.hidden = !a.focus;
  if (!a.focus) return;
  if (!askMap) askMap = new LivingMap(el, { onSelect: (id) => { $("#ask-dialog").close(); openEntity(id); }, onEdge: () => {}, onExpand: () => {}, onMenu: () => {}, onPin: () => {}, onSelection: () => {} });
  askMap.setTheme(theme());
  const g = await api("graph", new URLSearchParams({ from: a.from, to: a.to, device: a.focus.slice("device:".length), top: 8, collapse: "1", sites: "1", dns: "0", anomalies: "0", networks: "1" })).catch(() => null);
  if (!g?.nodes?.length) { el.hidden = true; return; }
  askMap.show(g);
  askMap.fit();
}

// The model option, if the server has one. Off whenever the page loads, and turning
// it on for a model elsewhere needs saying yes to what that means.
let askConfigLoaded = false;
function loadAskConfig() {
  if (askConfigLoaded) return;
  askConfigLoaded = true;
  api("ask/config", new URLSearchParams()).then((c) => {
    if (!c.llm) return;
    $("#ask-model").hidden = false;
    $("#ask-llm-name").textContent = `Use ${c.llm.model} on ${c.llm.host}`;
    const warn = $("#ask-llm-warn");
    warn.textContent = `Questions asked this way send data about your network, such as device names and what they connect to, to ${c.llm.host}.`;
    if (c.llm.local) return;
    const box = $("#ask-llm");
    box.onchange = async () => {
      warn.hidden = !box.checked;
      if (!box.checked) return;
      const ok = await inputDialog({ title: `Send network data to ${c.llm.host}?`, text: `${c.llm.host} isn't on your network. Answering with ${c.llm.model} sends it device names, addresses and what they connect to. Nothing is sent until you ask a question.`, ok: "Send it", danger: true });
      if (!ok) { box.checked = false; warn.hidden = true; }
    };
  }).catch(() => { askConfigLoaded = false; });
}

function renderAnswer(a) {
  const box = $("#ask-answer");
  const asked = a.from && a.to ? `<p class="muted">From ${esc(stamp(a.from))} to ${esc(stamp(a.to))}${a.confidence ? ` · ${esc(a.confidence)} confidence` : ""}</p>` : "";
  drawAskMap(a).catch(() => {});
  box.innerHTML = `<p><b>${esc(a.answer || "No answer.")}</b></p>${a.model ? `<p class="muted">Written by the model ${esc(a.model)}, not by netgraph. Check what matters.</p>` : ""}${asked}
    ${(a.claims || []).map((c) => `<p>${esc(c.text)} ${(c.evidence || []).map((e) => `<button class="cite" data-kind="${esc(e.kind)}" data-id="${esc(e.id)}" data-ts="${e.ts || 0}">${esc(e.kind)}</button>`).join(" ")}</p>`).join("")}
    ${(a.gaps || []).length ? `<p class="muted">Gaps: ${esc(a.gaps.join("; "))}</p>` : ""}
    ${(a.plan || []).length ? `<details><summary>How I answered</summary><ol>${a.plan.map((p) => `<li><span class="badge">${esc(p.tool)}</span> ${esc(Object.entries(p.args || {}).map(([k, v]) => `${k}=${v}`).join(" "))}</li>`).join("")}</ol></details>` : ""}
    ${(a.followups || []).length ? `<p class="muted">Try: ${a.followups.map(esc).join(" · ")}</p>` : ""}`;
  box.querySelectorAll(".cite").forEach((b) => {
    b.onclick = () => {
      const kind = b.dataset.kind, id = b.dataset.id, ts = Number(b.dataset.ts);
      // A model's citation is a read it made; the plan below shows which.
      if (kind === "tool") return;
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
  loadAskConfig();
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
let recSettle = null;

// recView is the stretch of time the timeline shows, and the reel covers. It
// holds still as the head moves: the timeline is a map of time.
function recView() {
  const v = state.rec.view;
  const now = Date.now();
  if (v && state.to >= v.from && state.to <= v.to) return v;
  const first = dataRange?.first_ms || now - units.d;
  const to = Math.max(now, state.to);
  const from = Math.min(state.to - state.rec.lookback, Math.max(first, state.to - 6 * units.h));
  state.rec.view = { from, to };
  return state.rec.view;
}

function renderRecorder() {
  const bar = $("#recorder-bar");
  if (!bar) return;
  $("#recorder").setAttribute("aria-pressed", String(state.rec.on));
  bar.hidden = !state.rec.on;
  $("#event-rail").hidden = !state.rec.on;
  if (!state.rec.on) return;
  const { from: lo, to: hi } = recView();
  const head = $("#rec-head");
  head.min = String(lo);
  head.max = String(hi);
  head.step = "1000";
  head.value = String(state.to);
  $("#rec-time").textContent = stamp(state.to);
  $("#rec-play").textContent = state.rec.playing ? "❚❚" : "▶";
  $("#rec-lookback").value = String(state.rec.lookback);
  const f = $("#rec-follow");
  f.hidden = !state.rec.follow;
  f.textContent = state.rec.follow ? `Following ${state.rec.follow}` : "";
  $("#rec-unfollow").hidden = !state.rec.follow;
  $("#rec-diff").textContent = state.rec.diffA ? "Diff B" : "Diff A";
  $("#rec-loop").textContent = state.rec.loop?.b ? "Loop ✕" : state.rec.loop ? "Loop end" : "Loop";
  $("#rec-loop").setAttribute("aria-pressed", String(Boolean(state.rec.loop?.b)));
  renderTimeline(lo, hi);
}

// renderTimeline draws the track behind the slider: where the traffic is, the
// moments worth seeking to, and the older stretch only rollups can answer. The
// series is fetched at most once a minute for a given stretch of time.
let timelineData = { key: "", at: 0, series: null, markers: [], loading: false };
function renderTimeline(lo, hi) {
  const c = $("#rec-density");
  if (!c) return;
  const key = `${lo}|${hi}|${state.filter}|${state.rec.follow}`;
  const stale = timelineData.key !== key || Date.now() - timelineData.at > 60_000;
  if (stale && !timelineData.loading && c.clientWidth > 0) {
    timelineData.loading = true;
    const buckets = Math.max(Math.floor(c.clientWidth / 3), 30);
    const step = Math.max(Math.ceil((hi - lo) / buckets / 1000), 10);
    Promise.all([
      api("timeseries", { from: lo, to: hi, step: `${step}s` }).catch(() => null),
      api("reel/markers", { from: lo, to: hi }).catch(() => []),
    ]).then(([series, markers]) => {
      timelineData = { key, at: Date.now(), series, markers: markers || [], loading: false };
      if (state.rec.on) renderTimeline(lo, hi);
    });
  }
  const dpr = window.devicePixelRatio || 1;
  const W = c.clientWidth, H = c.clientHeight;
  c.width = W * dpr;
  c.height = H * dpr;
  const g = c.getContext("2d");
  g.scale(dpr, dpr);
  if (hi <= lo) return;
  const x = (t) => ((t - lo) / (hi - lo)) * W;
  const css = getComputedStyle(document.documentElement);
  // Older than raw retention: the Recorder can answer, but only by the hour.
  const raw = dataRange?.raw_from_ms;
  if (raw && raw > lo) {
    g.fillStyle = css.getPropertyValue("--bg-3").trim() || "#ddd";
    g.fillRect(0, 0, x(Math.min(raw, hi)), H);
  }
  const loop = state.rec.loop;
  if (loop?.a) {
    g.fillStyle = "rgba(124, 58, 237, .18)";
    const end = loop.b || state.to;
    g.fillRect(x(Math.min(loop.a, end)), 0, Math.max(Math.abs(x(end) - x(loop.a)), 1), H);
  }
  const bs = timelineData.series?.buckets;
  if (bs?.length) {
    const peak = Math.max(1, ...bs.map((b) => b.bytes_in + b.bytes_out));
    g.fillStyle = css.getPropertyValue("--accent").trim() || "#2563eb";
    const step = timelineData.series.step || 0;
    for (const b of bs) {
      const v = b.bytes_in + b.bytes_out;
      if (!v) continue;
      // Square-rooted: one huge transfer must not flatten every other moment.
      const h = Math.max(2, Math.sqrt(v / peak) * (H - 8));
      const x0 = x(b.ts), x1 = x(b.ts + step);
      g.fillRect(x0, H - h, Math.max(x1 - x0, 1), h);
    }
  }
  const colors = { anomaly: "#dc2626", annotation: "#7c3aed", bookmark: "#7c3aed", device_new: "#16a34a" };
  for (const m of timelineData.markers) {
    g.fillStyle = m.severity === "low" ? "#d97706" : colors[m.kind] || "#6b7280";
    g.fillRect(x(m.ts) - 1, 0, 2, 7);
  }
}

// The reel of the timeline's stretch of time, once per view of it.
let reel = null;
let reelKey = "";
let reelLoad = null;
function loadReel() {
  const v = recView();
  const opts = { ...graphOpts(), anomalies: "0" };
  const key = JSON.stringify([v, opts, state.filter, state.rec.follow]);
  if (key === reelKey && reel) return Promise.resolve(reel);
  if (key === reelKey && reelLoad) return reelLoad;
  reelKey = key;
  const load = track(api("reel", { ...opts, from: v.from, to: v.to })).then((r) => {
    if (reelKey === key) reel = r;
    return r;
  }).finally(() => { if (reelLoad === load) reelLoad = null; });
  reelLoad = load;
  return load;
}

function drawFrame() {
  if (state.tab !== "graph" || !reel || !state.rec.on) return;
  diagram.applyFrame(reelFrame(reel, state.to, state.rec.lookback), state.rec.lookback);
}

// scrubTo moves the head with nothing asked of the server: the map draws from
// the reel straight away. The tables and summary catch up when it stops.
function scrubTo(ts, { settle = true } = {}) {
  const v = recView();
  const t = Math.round(Math.min(Math.max(ts, v.from), Math.min(v.to, Date.now())));
  state.rec.at = t;
  state.to = t;
  state.span = state.rec.lookback;
  state.live = false;
  if (state.rec.diff) clearDiff();
  $("#rec-head").value = String(t);
  $("#rec-time").textContent = stamp(t);
  drawFrame();
  if (settle) {
    clearTimeout(recSettle);
    recSettle = setTimeout(refresh, 250);
  }
}

function setRecAt(ts) {
  clearTimeout(recSettle);
  state.rec.at = Math.max(0, Math.round(ts));
  state.to = state.rec.at;
  state.span = state.rec.lookback;
  state.live = false;
  return refresh();
}

let playRun = 0;
function stopPlay() {
  const was = state.rec.playing;
  state.rec.playing = false;
  playRun++;
  clearTimeout(recTimer);
  recTimer = null;
  renderRecorder();
  if (was && state.tab === "graph" && state.rec.on) refresh();
}

const atEnd = (t) => t >= Math.min(recView().to, Date.now());

// togglePlay runs the head forward by real elapsed time times the speed. On the
// map that is every animation frame, drawn from the reel with no requests. A
// table has to ask the server, so it waits for each answer before the next.
function togglePlay() {
  if (state.rec.playing) return stopPlay();
  state.rec.playing = true;
  state.rec.at = Math.min(state.rec.at, Date.now());
  if (atEnd(state.rec.at)) {
    const l = state.rec.loop;
    state.rec.at = l?.a || recView().from;
    state.to = state.rec.at;
  }
  const run = ++playRun;
  let last = performance.now();
  const speed = () => Number($("#rec-speed").value) || 1;
  const advance = (now) => {
    let next = state.rec.at + (now - last) * speed();
    last = now;
    const l = state.rec.loop;
    if (l?.b && next >= Math.max(l.a, l.b)) next = Math.min(l.a, l.b);
    return next;
  };
  const frame = (now) => {
    if (run !== playRun) return;
    const next = advance(now);
    if (atEnd(next)) { scrubTo(next, { settle: false }); stopPlay(); return; }
    scrubTo(next, { settle: false });
    requestAnimationFrame(frame);
  };
  const tick = async () => {
    if (run !== playRun) return;
    const started = performance.now();
    const next = advance(started);
    if (atEnd(next)) {
      setRecAt(Date.now());
      stopPlay();
      return;
    }
    await setRecAt(next);
    if (run !== playRun) return;
    recTimer = setTimeout(tick, Math.max(0, 1000 - (performance.now() - started)));
  };
  if (state.tab === "graph" && reel) requestAnimationFrame(frame);
  else recTimer = setTimeout(tick, 1000);
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
    state.rec.view = null;
    if (state.live) setLive(false);
    state.live = false;
  } else {
    leaveRecorder();
  }
  renderRecorder();
  refresh();
}

// leaveRecorder drops what only makes sense inside it. Following filters every
// view, and its controls are leaving with the bar.
function leaveRecorder() {
  state.rec.follow = "";
  state.rec.loop = null;
  stopPlay();
  clearDiff();
  diagram.applyFrame(null);
  lastView = null;
}

function follow(id) {
  if (!id) return;
  state.rec.follow = id;
  state.rec.on = true;
  state.rec.at = state.to;
  state.rec.lookback = state.span > 0 && state.span <= units.h ? state.span : 5 * units.m;
  state.span = state.rec.lookback;
  state.rec.view = null;
  state.live = false;
  renderRecorder();
  refresh();
}

// jumpMarker seeks to the next or previous moment on the timeline.
function jumpMarker(dir) {
  const ms = timelineData.markers;
  const t = state.to;
  const m = dir > 0 ? ms.find((x) => x.ts > t + 500) : [...ms].reverse().find((x) => x.ts < t - 500);
  if (!m) { setStatus(dir > 0 ? "no later marks in view" : "no earlier marks in view"); return; }
  setStatus(m.title);
  // A little after the moment, so its traffic is in the frame.
  setRecAt(Math.min(m.ts + 1000, recView().to));
}

function zoomTimeline(e) {
  e.preventDefault();
  const v = recView();
  const r = $("#rec-density").getBoundingClientRect();
  const at = v.from + ((e.clientX - r.left) / r.width) * (v.to - v.from);
  const k = Math.exp(e.deltaY * 0.002);
  const now = Date.now();
  const floor = Math.min(dataRange?.first_ms || now - 30 * units.d, state.to);
  const span = Math.min(Math.max((v.to - v.from) * k, Math.max(10 * units.m, state.rec.lookback * 2)), Math.max(now, state.to) - floor);
  let from = at - ((at - v.from) / (v.to - v.from)) * span;
  from = Math.max(floor, Math.min(from, state.to));
  const to = Math.max(Math.min(from + span, Math.max(now, state.to)), state.to);
  state.rec.view = { from: Math.min(from, to - span), to };
  renderRecorder();
  clearTimeout(recSettle);
  recSettle = setTimeout(refresh, 300);
}

async function renderRail(seq) {
  const box = $("#event-rail");
  if (!box) return;
  if (!state.rec.on) { box.hidden = true; return; }
  if (state.rec.diff) return;
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
  // Findings belong on the rail too, whatever their status.
  const found = await api("findings", new URLSearchParams({ since: state.to - units.d, to: state.to + 1, limit: 40, ...(state.rec.follow.startsWith("device:") ? { device: state.rec.follow } : {}) })).catch(() => null);
  if (seq !== refreshSeq) return;
  for (const f of found?.findings || []) {
    if (f.last_seen <= state.to) events.push({ ts: f.last_seen, kind: "finding", title: f.summary, entity: f.device || f.entity || "" });
  }
  events.sort((a, b) => b.ts - a.ts);
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

function clearDiff() {
  if (!state.rec.diff) return;
  state.rec.diff = null;
  diagram.setDiff(null);
  $("#diff-legend").hidden = true;
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
  state.rec.diff = { a, b: state.to };
  box.hidden = false;
  box.innerHTML = `<div class="rail-head"><b>Diff</b><span class="muted">${esc(stamp(a))} → ${esc(stamp(state.to))}</span></div><p class="muted">Comparing…</p>`;
  // On the map: both moments must be in the reel, so widen it if A is not.
  try {
    if (state.tab === "graph") {
      const v = recView();
      if (a - state.rec.lookback < v.from) {
        state.rec.view = { from: a - state.rec.lookback, to: v.to };
        renderRecorder();
      }
      const r = await loadReel();
      if (diagram.graph !== r.graph) diagram.show(r.graph, { keepView: true, spanMS: state.rec.lookback });
      const fa = reelFrame(r, a, state.rec.lookback), fb = reelFrame(r, state.to, state.rec.lookback);
      diagram.setDiff(reelDiff(fa, fb));
      diagram.applyFrame(new Map([...fa, ...fb]), state.rec.lookback);
      $("#diff-legend").hidden = false;
    }
    const d = await api("diff", { at_a: a, at_b: state.to, lookback: `${Math.round(state.rec.lookback / 1000)}s` });
    const row = (kind, x) => `<li><span class="badge">${esc(kind)}</span> <b>${esc(x.kind)}</b> ${esc(x.label || x.key)}${x.before || x.after ? ` <span class="muted">${esc(x.before || "")}${x.before && x.after ? " → " : ""}${esc(x.after || "")}</span>` : ""}</li>`;
    const lines = [
      ...(d.added || []).map((x) => row("added", x)),
      ...(d.removed || []).map((x) => row("removed", x)),
      ...(d.changed || []).map((x) => row("changed", x)),
    ];
    box.innerHTML = `<div class="rail-head"><b>Diff</b><span class="muted">${esc(stamp(a))} → ${esc(stamp(state.to))}</span> <button type="button" id="diff-clear">Clear</button></div>
      ${lines.length ? `<ul class="rail-list">${lines.join("")}</ul>` : `<p class="muted">No differences in devices, destinations, DNS, Wi-Fi, sensors or anomalies.</p>`}
      ${(d.gaps || []).map((g) => `<p class="muted">gap: ${esc(g)}</p>`).join("")}`;
    $("#diff-clear").onclick = () => { clearDiff(); drawFrame(); refresh(); };
  } catch (e) {
    box.innerHTML = `<p class="muted">${esc(e.message)}</p>`;
  }
  renderRecorder();
}

// --- saved views ----------------------------------------------------------------------

function savedViews() {
  try {
    const v = JSON.parse(store.get("netgraph.views") || "[]");
    return Array.isArray(v) ? v : [];
  } catch { return []; }
}

function saveViews(list) {
  store.set("netgraph.views", JSON.stringify(list));
  renderViewSelect();
}

function renderViewSelect() {
  $("#view-select").innerHTML = `<option value="">Saved views</option>` + savedViews().map((v, i) => `<option value="${i}">${esc(v.name)}</option>`).join("");
}

async function saveCurrentView() {
  const name = await inputDialog({ title: "Save this view", text: "Keeps the view, filter, map options and window length, in this browser. Opening it shows that length up to now.", input: true, placeholder: "Name", ok: "Save" });
  if (!name) return;
  const list = savedViews().filter((v) => v.name !== name);
  list.push({ name, tab: state.tab, filter: state.filter, span: state.span, gopts: { ...state.gopts } });
  saveViews(list);
  setStatus(`Saved “${name}”`);
}

function openView(v) {
  if (!v || !areaOf(v.tab)) return;
  state.filter = String(v.filter || "");
  $("#filter").value = state.filter;
  renderChips();
  state.span = Number(v.span) >= 10_000 ? Number(v.span) : state.span;
  if (v.gopts && typeof v.gopts === "object") Object.assign(state.gopts, v.gopts);
  syncGraphInputs();
  state.to = Date.now();
  selectTab(v.tab);
  if (!state.live) setLive(true);
}

function syncGraphInputs() {
  for (const [id, k] of [["#g-collapse", "collapse"], ["#g-dns", "dns"], ["#g-sites", "sites"], ["#g-anomalies", "anomalies"], ["#g-networks", "networks"], ["#g-identity", "identity"]]) {
    $(id).checked = state.gopts[k];
  }
  $("#g-top").value = state.gopts.top;
}

// --- filter chips and suggestions -------------------------------------------------------

// What a device's MAC in a filter is called, as far as this page has seen.
const chipLabels = new Map();

function renderChips() {
  const box = $("#filter-chips");
  const list = tokens(state.filter);
  box.hidden = !list.length;
  box.replaceChildren();
  list.forEach((tok, i) => {
    const chip = document.createElement("span");
    chip.className = "chip";
    const text = document.createElement("span");
    text.textContent = chipLabels.get(tok) || tok;
    text.title = tok;
    const x = document.createElement("button");
    x.type = "button";
    x.textContent = "×";
    x.setAttribute("aria-label", `Remove ${tok}`);
    x.onclick = () => {
      const rest = tokens(state.filter);
      rest.splice(i, 1);
      applyFilterText(rest.join(" "));
    };
    chip.append(text, x);
    box.append(chip);
  });
  if (list.length > 1) {
    const clear = document.createElement("button");
    clear.type = "button";
    clear.className = "chip-clear";
    clear.textContent = "Clear all";
    clear.onclick = () => applyFilterText("");
    box.append(clear);
  }
}

function applyFilterText(text) {
  state.filter = text;
  $("#filter").value = text;
  renderChips();
  return refresh();
}

function filterSuggest() {
  const input = $("#filter"), list = $("#filter-suggest");
  let items = [], active = -1, seq = 0, timer;
  const close = () => { list.hidden = true; input.setAttribute("aria-expanded", "false"); input.removeAttribute("aria-activedescendant"); items = []; active = -1; };
  const show = () => {
    if (!items.length) { close(); return; }
    list.replaceChildren(...items.map((it, i) => {
      const li = document.createElement("li");
      li.id = `fs-${i}`;
      li.setAttribute("role", "option");
      li.dataset.i = i;
      li.className = i === active ? "active" : "";
      const b = document.createElement("b");
      b.textContent = it.label || it.text;
      li.append(b);
      if (it.hint) { const s = document.createElement("span"); s.className = "muted"; s.textContent = ` ${it.hint}`; li.append(s); }
      return li;
    }));
    list.hidden = false;
    input.setAttribute("aria-expanded", "true");
    if (active >= 0) input.setAttribute("aria-activedescendant", `fs-${active}`);
    else input.removeAttribute("aria-activedescendant");
  };
  const accept = (it) => {
    const { head } = lastToken(input.value);
    if (it.label) chipLabels.set(it.text, it.label);
    if (it.partial) {
      input.value = head + it.text;
      suggest();
      input.focus();
      return;
    }
    close();
    applyFilterText(head + it.text);
    input.value = state.filter + " ";
    input.focus();
  };
  const suggest = () => {
    clearTimeout(timer);
    const { word } = lastToken(input.value);
    const n = ++seq;
    if (!word) { close(); return; }
    items = localSuggestions(word);
    active = -1;
    show();
    const i = word.indexOf(":");
    const kind = i > 0 ? searched[word.slice(0, i)] : "";
    const q = i > 0 ? word.slice(i + 1) : "";
    if (!kind || q.length < 2) return;
    timer = setTimeout(async () => {
      let rs;
      try { rs = await api("search", new URLSearchParams({ q, limit: 12 })); } catch { return; }
      if (n !== seq) return;
      items = (rs || []).filter((r) => r.kind === kind).slice(0, 8).map((r) => ({ text: `${word.slice(0, i)}:${r.key}`, label: r.label !== r.key ? r.label : "", hint: r.label !== r.key ? r.key : "" }));
      active = -1;
      show();
    }, 200);
  };
  let typing;
  input.oninput = () => {
    suggest();
    clearTimeout(typing);
    typing = setTimeout(() => { state.filter = input.value.trim(); renderChips(); refresh(); }, 400);
  };
  input.onkeydown = (e) => {
    if ((e.key === "ArrowDown" || e.key === "ArrowUp") && items.length) {
      e.preventDefault();
      active = e.key === "ArrowDown" ? (active + 1) % items.length : (active <= 0 ? items.length : active) - 1;
      show();
    } else if ((e.key === "Enter" || e.key === "Tab") && active >= 0) {
      e.preventDefault();
      accept(items[active]);
    } else if (e.key === "Enter") {
      close();
      clearTimeout(typing);
      state.filter = input.value.trim();
      renderChips();
      refresh();
    } else if (e.key === "Escape") {
      if (!list.hidden) close();
      else input.blur();
    }
  };
  list.onmousedown = (e) => { const li = e.target.closest("li[data-i]"); if (li) { e.preventDefault(); accept(items[Number(li.dataset.i)]); } };
  input.onblur = () => setTimeout(close, 100);
}

// --- command palette ----------------------------------------------------------------------

function commands() {
  const go = [["Home", "home", "1"], ["Map", "map", "2"], ["Devices", "devices", "3"], ["Activity", "activity", "4"], ["Findings", "findings", "5"], ["Wi-Fi", "wifi", "6"], ["Settings", "settings", "7"]]
    .map(([label, area, key]) => ({ label: `Go to ${label}`, key, run: () => selectArea(area) }));
  const views = [["Connections", "flows"], ["Destinations", "destinations"], ["DNS", "dns"], ["Facts", "facts"], ["Pulse", "pulse"], ["Presence", "presence"], ["Devices to confirm", "links"], ["Internet quality", "quality"], ["Wi-Fi airspace", "airspace"], ["Findings inbox", "findings"], ["Anomalies in this window", "anomalies"], ["Incidents", "incidents"], ["Insights", "insights"], ["Policy builder", "policy"], ["Sensors", "sensors"]]
    .map(([label, t]) => ({ label: `Go to ${label}`, run: () => selectTab(t) }));
  const onMap = (f) => () => { if (state.tab !== "graph") selectTab("graph"); f(); };
  return [
    ...go, ...views,
    { label: state.live ? "Stop following Live" : "Follow Live", key: "l", run: () => setLive(!state.live) },
    { label: state.rec.on ? "Leave the Recorder" : "Open the Recorder", key: "t", run: onMap(() => toggleRecorder()) },
    { label: "Ask netgraph", key: "?", run: openAsk },
    { label: "Find a device or address", key: "f", run: () => $("#search").focus() },
    { label: "Filter this view", key: "/", run: () => $("#filter").focus() },
    { label: "Add a note", run: () => openNote() },
    { label: "Bookmark this moment", run: saveBookmark },
    { label: "What-if: test a policy", run: () => openWhatIf() },
    { label: "Fit the map to the screen", key: "0", run: onMap(() => diagram.fit()) },
    { label: "Re-arrange the map", run: onMap(() => diagram.rearrange()) },
    { label: privacy.on ? "Turn off privacy mode" : "Turn on privacy mode", run: () => setPrivacy(!privacy.on) },
    { label: "Toggle dark mode", run: () => setTheme(theme() === "dark" ? "light" : "dark") },
    { label: "Save this view", run: saveCurrentView },
    { label: "Add a sensor", run: () => selectTab("settings") },
    ...savedViews().map((v) => ({ label: `Open view: ${v.name}`, run: () => openView(v) })),
  ];
}

function palette() {
  const dlg = $("#palette"), input = $("#palette-q"), list = $("#palette-list");
  let items = [], active = 0, seq = 0, timer, found = [];
  const draw = () => {
    list.replaceChildren(...items.map((it, i) => {
      if (it.head) {
        const li = document.createElement("li");
        li.className = "palette-head";
        li.setAttribute("role", "presentation");
        li.textContent = it.head;
        return li;
      }
      const li = document.createElement("li");
      li.id = `pl-${i}`;
      li.setAttribute("role", "option");
      li.dataset.i = i;
      li.setAttribute("aria-selected", String(i === active));
      const name = document.createElement("span");
      name.textContent = it.label;
      li.append(name);
      if (it.sub) { const s = document.createElement("span"); s.className = "muted mono"; s.textContent = it.sub; li.append(s); }
      if (it.key) { const k = document.createElement("kbd"); k.textContent = it.key; li.append(k); }
      return li;
    }));
    input.setAttribute("aria-activedescendant", `pl-${active}`);
    list.querySelector(`[data-i="${active}"]`)?.scrollIntoView({ block: "nearest" });
  };
  const build = () => {
    const q = input.value.trim();
    const out = [];
    const when = parseWhen(q);
    if (when) {
      out.push({ head: "Go to a time" }, {
        label: when.label,
        sub: when.live ? "up to now" : "",
        run: () => {
          if (state.live !== Boolean(when.live)) setLive(Boolean(when.live));
          state.to = when.live ? Date.now() : when.to;
          state.span = when.span;
          if (state.rec.on) state.rec.at = state.to;
          selectTab(plainTabs.has(state.tab) ? "graph" : state.tab);
        },
      });
    }
    const matched = commands().map((c) => ({ ...c, score: fuzzy(q, c.label) })).filter((c) => c.score > 0);
    if (q) matched.sort((a, b) => b.score - a.score);
    if (matched.length) out.push({ head: "Commands" }, ...matched.slice(0, q ? 8 : 40));
    if (found.length) {
      out.push({ head: "On your network" }, ...found.map((r) => ({ label: r.label, sub: r.label !== r.key ? `${r.kind} ${r.key}` : r.kind, run: () => (r.kind === "device" ? openPassport(r.id) : openEntity(r.id)) })));
    }
    items = out;
    active = items.findIndex((x) => !x.head);
    draw();
  };
  const pick = (i) => {
    const it = items[i];
    if (!it?.run) return;
    dlg.close();
    it.run();
  };
  const move = (dir) => {
    if (!items.length) return;
    let i = active;
    do { i = (i + dir + items.length) % items.length; } while (items[i].head);
    active = i;
    draw();
  };
  input.oninput = () => {
    clearTimeout(timer);
    found = [];
    build();
    const q = input.value.trim();
    const n = ++seq;
    if (q.length < 2) return;
    timer = setTimeout(async () => {
      let rs;
      try { rs = await api("search", new URLSearchParams({ q, limit: 8 })); } catch { return; }
      if (n !== seq) return;
      found = rs || [];
      build();
    }, 180);
  };
  input.onkeydown = (e) => {
    if (e.key === "ArrowDown") { e.preventDefault(); move(1); }
    else if (e.key === "ArrowUp") { e.preventDefault(); move(-1); }
    else if (e.key === "Enter") { e.preventDefault(); pick(active); }
  };
  list.onclick = (e) => { const li = e.target.closest("li[data-i]"); if (li) pick(Number(li.dataset.i)); };
  dlg.onclick = (e) => { if (e.target === dlg) dlg.close(); };
  return () => {
    if (dlg.open) { dlg.close(); return; }
    input.value = "";
    found = [];
    build();
    dlg.showModal();
    input.focus();
  };
}

// --- wiring ---------------------------------------------------------------------------

// Which view of each area was last open, so coming back returns to it.
const lastInArea = {};

function selectTab(t) {
  state.tab = t;
  const area = areaOf(t);
  lastInArea[area] = t;
  for (const b of $$(".tabs button")) {
    b.setAttribute("aria-selected", String(b.dataset.area === area));
    b.tabIndex = b.dataset.area === area ? 0 : -1;
  }
  for (const v of $$(".view")) v.hidden = v.id !== `view-${t}`;
  const sub = $("#subtabs"), spec = areas[area];
  sub.hidden = spec.tabs.length < 2;
  sub.innerHTML = sub.hidden ? "" : spec.tabs.map(([id, label]) => `<button type="button" data-tab="${id}" aria-current="${id === t ? "page" : "false"}">${label}</button>`).join("") +
    (spec.tools ? `<span class="spacer"></span>${spec.tools}` : "");
  document.body.toggleAttribute("data-plain", plainTabs.has(t));
  syncFeed();
  return refresh();
}

const selectArea = (area) => selectTab(lastInArea[area] || areas[area].tabs[0][0]);

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
      state.rec.follow = "";
      applyFilterText("");
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

  $("#back").onclick = () => setWindow(state.to - state.span / 2, state.span);
  $("#fwd").onclick = () => setWindow(state.to + state.span / 2, state.span);
  $("#zoomout").onclick = () => setWindow(state.to + state.span / 2, state.span * 2, { live: state.live });
  $("#live").onclick = () => setLive(!state.live);
  $("#recorder").onclick = () => toggleRecorder();
  $("#rec-play").onclick = togglePlay;
  $("#rec-back").onclick = () => setRecAt(state.rec.at - Math.max(1000, state.rec.lookback / 5));
  $("#rec-fwd").onclick = () => setRecAt(Math.min(Date.now(), state.rec.at + Math.max(1000, state.rec.lookback / 5)));
  $("#rec-now").onclick = () => setRecAt(Date.now());
  $("#rec-note").onclick = () => openNote();
  $("#rec-bookmark").onclick = saveBookmark;
  $("#rec-capsule").onclick = exportCapsule;
  $("#note-save").onclick = saveNote;
  $("#rec-diff").onclick = renderDiffBox;
  $("#rec-unfollow").onclick = () => { state.rec.follow = ""; refresh(); };
  $("#rec-head").oninput = () => scrubTo(Number($("#rec-head").value));
  $(".rec-track").addEventListener("wheel", zoomTimeline, { passive: false });
  $("#rec-prev").onclick = () => jumpMarker(-1);
  $("#rec-next").onclick = () => jumpMarker(1);
  $("#rec-loop").onclick = () => {
    const l = state.rec.loop;
    state.rec.loop = !l ? { a: state.to, b: 0 } : !l.b ? { a: l.a, b: state.to } : null;
    renderRecorder();
  };
  $("#rec-lookback").onchange = () => {
    state.rec.lookback = Number($("#rec-lookback").value) || 300000;
    state.rec.view = null;
    setRecAt(state.rec.at);
  };
  $("#rec-rail").onchange = () => refresh();
  // The speed is read as it plays.
  for (const b of $$(".presets button")) b.onclick = () => setWindow(Date.now(), parseSpan(b.dataset.span), { live: state.live });
  const fromTo = () => {
    const f = new Date($("#from").value).getTime(), t = new Date($("#to").value).getTime();
    if (f < t) setWindow(t, t - f);
  };
  $("#from").onchange = fromTo;
  $("#to").onchange = fromTo;
  filterSuggest();
  renderChips();
  renderViewSelect();
  $("#view-save").onclick = saveCurrentView;
  $("#view-select").onchange = () => {
    const v = savedViews()[Number($("#view-select").value)];
    $("#view-select").value = "";
    openView(v);
  };
  const togglePalette = palette();
  $("#palette-open").onclick = togglePalette;
  $("#palette-open").textContent = /mac/i.test(navigator.platform) ? "⌘K" : "Ctrl K";
  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); togglePalette(); }
  });
  $("#passport-body").onclick = passportClick;
  $("#findings-body").onclick = findingsClick;
  $("#pulse-pause").onclick = () => {
    pulse.setPaused(!pulse.paused);
    $("#pulse-pause").setAttribute("aria-pressed", String(pulse.paused));
    $("#pulse-pause").textContent = pulse.paused ? "Resume" : "Pause";
  };
  $("#pulse-clear").onclick = () => pulse.clear();
  $("#pulse-q").oninput = () => { pulse.query = $("#pulse-q").value.trim().toLowerCase(); };
  $("#pulse-type").onchange = () => { pulse.type = $("#pulse-type").value; };
  const tabButtons = $$(".tabs button");
  for (const [i, b] of tabButtons.entries()) {
    b.onclick = () => selectArea(b.dataset.area);
    b.onkeydown = (e) => {
      if (e.key !== "ArrowRight" && e.key !== "ArrowLeft" && e.key !== "Home" && e.key !== "End") return;
      e.preventDefault();
      const n = e.key === "Home" ? 0 : e.key === "End" ? tabButtons.length - 1
        : (i + (e.key === "ArrowRight" ? 1 : -1) + tabButtons.length) % tabButtons.length;
      tabButtons[n].focus();
      selectArea(tabButtons[n].dataset.area);
    };
  }
  $("#subtabs").onclick = (e) => {
    if (e.target.closest("#whatif-open")) { openWhatIf(); return; }
    const b = e.target.closest("[data-tab]");
    if (b) selectTab(b.dataset.tab);
  };
  $("#home-body").onclick = homeClick;
  $("#settings-body").onclick = settingsClick;
  document.addEventListener("click", copyClick);
  // Home keeps itself current on any window, Live or not; without data it also
  // watches for the first packets.
  setInterval(() => {
    if (state.tab !== "home" || document.hidden || Date.now() - homeState.at < homePoll()) return;
    renderHome(refreshSeq).catch(() => {});
  }, 3000);
  $("#summary").onclick = (e) => { const a = e.target.closest("[data-tab]"); if (a) selectTab(a.dataset.tab); };
  for (const [id, k] of [["#g-collapse", "collapse"], ["#g-dns", "dns"], ["#g-sites", "sites"], ["#g-anomalies", "anomalies"], ["#g-networks", "networks"], ["#g-identity", "identity"]]) {
    $(id).onchange = () => { state.gopts[k] = $(id).checked; refresh(); };
  }
  $("#g-top").onchange = () => { state.gopts.top = Number($("#g-top").value) || 15; refresh(); };
  $("#connect").onclick = () => askToken().then((t) => { if (t) refresh(); });
  const sev = $("#anomaly-sev");
  if (sev) sev.onchange = () => refresh();
  const dg = $("#dest-group");
  if (dg) dg.onchange = () => refresh();
  const inc = $("#incident-status");
  if (inc) inc.onchange = () => refresh();
  // Only a phone shows this: its screen is for the map, not for the options.
  $("#g-more").onclick = () => {
    const open = $(".graph-tools").classList.toggle("open");
    $("#g-more").setAttribute("aria-expanded", String(open));
  };
  $("#g-fit").onclick = () => diagram.fit();
  $("#g-arrange").onclick = () => diagram.rearrange();
  $("#g-unhide").onclick = () => { diagram.showHidden(); refresh(); };
  // Exports are the server's d2 drawing of the same graph: a file for other
  // tools, laid out for paper rather than for this map.
  $("#g-svg").onclick = () => track(api("graph", { ...graphOpts(), format: "svg", theme: theme() }, true))
    .then((svg) => download(`netgraph-${fileStamp()}.svg`, svg, "image/svg+xml")).catch(() => {});
  $("#g-d2").onclick = () => track(api("graph", { ...graphOpts(), format: "d2" }, true))
    .then((d2) => download(`netgraph-${fileStamp()}.d2`, d2, "text/plain")).catch(() => {});
  $("#g-png").onclick = () => {
    const a = document.createElement("a");
    a.href = diagram.toPNG();
    a.download = `netgraph-${fileStamp()}.png`;
    a.click();
  };
  document.addEventListener("pointerdown", (e) => { if (!e.target.closest("#map-menu")) closeMapMenu(); });
  matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => { diagram.setTheme(theme()); });
  $("#ask-open").onclick = openAsk;
  $("#whatif-run").onclick = runWhatIf;
  wirePolicy();
  $("#ask-form").onsubmit = async (e) => {
    e.preventDefault();
    const q = $("#ask-q").value.trim();
    if (!q) return;
    $("#ask-answer").innerHTML = `<p class="muted">Investigating…</p>`;
    try {
      const a = await send("POST", "ask", { q, from: String(state.to - state.span), to: String(state.to), tz: -new Date().getTimezoneOffset(), llm: $("#ask-llm").checked });
      renderAnswer(a);
    } catch (err) {
      $("#ask-answer").innerHTML = `<p class="muted">${esc(err.message)}</p>`;
    }
  };
  $("#panel-close").onclick = closePanel;
  $("#panel").addEventListener("click", (e) => {
    const a = e.target.closest("a[data-passport]");
    if (a) openPassport(a.dataset.passport);
  });
  $("#panel").addEventListener("submit", async (e) => {
    const form = e.target.closest("form.profile");
    if (!form) return;
    e.preventDefault();
    const out = form.querySelector("output");
    try {
      await send("PUT", `devices/${encodeURIComponent(state.open.slice("device:".length))}/profile`, {
        type: form.elements.type.value,
        owner: form.elements.owner.value,
        groups: form.elements.groups.value.split(/[\s,]+/).filter(Boolean),
      });
      out.textContent = "Saved";
      refresh();
      openEntity(state.open);
    } catch (err) { out.textContent = err.message; }
  });
  $("#quality-body").onclick = (e) => { const b = e.target.closest("[data-open]"); if (b) openEntity(b.dataset.open); };
  $("#presence-body").onclick = (e) => { const b = e.target.closest("[data-open]"); if (b) openEntity(b.dataset.open); };
  $("#links-body").onclick = async (e) => {
    const b = e.target.closest("[data-link]");
    if (!b) return;
    b.disabled = true;
    try {
      await send("POST", `devices/${encodeURIComponent(b.dataset.mac)}/link`, { same: b.dataset.same, decision: b.dataset.link });
      homeState.at = 0;
      refresh();
    } catch (err) { setStatus(err.message, true); b.disabled = false; }
  };
  $("#theme").onclick = () => { setTheme(theme() === "dark" ? "light" : "dark"); refresh(); };
  document.addEventListener("keydown", (e) => {
    if (e.target.matches("input, select, textarea")) return;
    const k = e.key;
    if (k === "Escape") closePanel();
    else if (k === "[") { if (!plainTabs.has(state.tab)) $("#back").click(); }
    else if (k === "]") { if (!plainTabs.has(state.tab)) $("#fwd").click(); }
    else if (k === "l") { if (!plainTabs.has(state.tab)) $("#live").click(); }
    else if (k === "t") {
      e.preventDefault();
      if (plainTabs.has(state.tab)) selectTab("graph");
      $("#recorder").click();
    }
    else if (k === " ") { if (state.rec.on && !e.target.matches("button, a, input, select, textarea")) { e.preventDefault(); togglePlay(); } }
    else if (k === "/") { if (!plainTabs.has(state.tab)) { e.preventDefault(); $("#filter").focus(); } }
    else if (k === "?") { e.preventDefault(); openAsk(); }
    else if (k === "f") { e.preventDefault(); $("#search").focus(); }
    else if (k >= "1" && Number(k) <= $$(".tabs button").length) selectArea($$(".tabs button")[Number(k) - 1].dataset.area);
  });
  brush();
  addEventListener("resize", () => renderSpark(series));
  // A pasted or edited link changes only the hash: follow it.
  addEventListener("hashchange", () => {
    if (location.hash.slice(1) === lastHash) return;
    const wasLive = state.live;
    loadHash();
    $("#filter").value = state.filter;
    renderChips();
    renderWindow();
    syncGraphInputs();
    const changed = state.live !== wasLive;
    if (changed) setLive(state.live);
    if (!changed || !state.live) selectTab(state.tab);
    if (state.open) openEntity(state.open);
    else $("#panel").hidden = true;
  });
  search();
  document.body.classList.toggle("privacy", privacy.on);
  $("#privacy-off").onclick = () => setPrivacy(false);
  loadMe();
  // Installable, and survives the server restarting. Needs HTTPS or localhost.
  if ("serviceWorker" in navigator) navigator.serviceWorker.register("sw.js").catch(() => {});
  selectTab(state.tab);
  if (state.live) setLive(true);
  // A link with open= starts with those details.
  if (state.open) openEntity(state.open);
}

init();
