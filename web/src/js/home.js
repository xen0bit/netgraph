// The landing page: is everything reporting, what is new since the last visit,
// who is here, who is busy. Drawn from GET /api/v1/home; every value that came
// off the network goes through esc().
import { esc, bytes, stamp, clock, ago, units } from "./util.js";
import { typeName } from "./devices.js";

const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

// status is the sentence at the top: never a colour alone.
function status(h) {
  const asOf = h.as_of ? ago(h.now - h.as_of) : "";
  const live = h.sensors.filter((s) => !s.quiet).length;
  switch (h.state) {
    case "ok": return ["ok", "●", `${plural(live, "sensor")} reporting`, h.sensors.length > live ? `${h.sensors.length - live} quiet · newest data ${asOf}` : `newest data ${asOf}`];
    case "quiet": return ["warn", "▲", "No sensor is reporting", `Everything below is as of ${stamp(h.as_of)}, ${asOf}.`];
    default: return ["info", "■", "Showing recorded data", `No sensor is connected. The data ends ${stamp(h.as_of)}, ${asOf}.`];
  }
}

function sinceTitle(h, firstVisit) {
  if (firstVisit) return "In the last day";
  if (h.since_clamped) return "In the last 7 days";
  return `Since you were last here, ${ago(h.as_of - h.since)}`;
}

const deviceSub = (d) => [d.owner, d.type ? typeName(d.type) : d.randomized ? "private MAC" : d.vendor_short || d.vendor || d.ips?.[0] || d.mac].filter(Boolean).join(" · ");

// trafficChart is one measure over the day: one colour, one axis, a tooltip per
// bar. Clicking a bar opens the map at that moment.
function trafficChart(t) {
  const buckets = t?.buckets || [];
  if (!buckets.length) return `<p class="muted">Nothing moved in the last day.</p>`;
  const total = (b) => b.bytes_in + b.bytes_out;
  const peak = Math.max(1, ...buckets.map(total));
  const sum = buckets.reduce((a, b) => a + total(b), 0);
  const end = buckets[buckets.length - 1].ts + t.step;
  const from = end - units.d;
  const byTS = new Map(buckets.map((b) => [b.ts, b]));
  const start = Math.ceil(from / t.step) * t.step;
  const bars = [];
  for (let ts = start; ts < end; ts += t.step) {
    const b = byTS.get(ts);
    const v = b ? total(b) : 0;
    const height = v ? Math.max(3, (v / peak) * 100) : 0;
    const tip = `${stamp(ts)} · ${bytes(v)}`;
    bars.push(`<button type="button" class="tbar" data-jump="${ts}" data-step="${t.step}" title="${esc(tip)}" aria-label="${esc(tip)}"><span style="height:${height.toFixed(1)}%"></span></button>`);
  }
  return `<div class="tchart" role="group" aria-label="${esc(`Traffic over the last day: ${bytes(sum)} in all, at most ${bytes(peak)} per ${Math.round(t.step / units.m)} minutes`)}">${bars.join("")}</div>
    <div class="taxis"><span>${esc(stamp(start))}</span><span>peak ${esc(bytes(peak))} per ${Math.round(t.step / units.m)} min</span><span>${esc(clock(end))}</span></div>`;
}

function talkers(list) {
  if (!list.length) return `<p class="muted">Nothing moved in the last hour.</p>`;
  const total = (d) => d.bytes_in + d.bytes_out;
  const peak = Math.max(1, ...list.map(total));
  return `<ul class="talkers">${list.map((d) => `<li><button type="button" class="row-link" data-open="${esc(d.id)}">
    <span class="talker-name">${esc(d.label)}</span><span class="talker-value" title="${esc(`sent ${bytes(d.bytes_out)}, received ${bytes(d.bytes_in)}`)}">${esc(bytes(total(d)))}</span>
    <span class="talker-bar"><span style="width:${((total(d) / peak) * 100).toFixed(1)}%"></span></span></button></li>`).join("")}</ul>`;
}

function people(list) {
  if (!list.length) return `<p class="muted">No device was active in the 10 minutes before the newest data.</p>`;
  const owners = [...new Set(list.map((d) => d.owner).filter(Boolean))].sort();
  const shown = list.slice(0, 24);
  const more = list.length - shown.length;
  return `${owners.length ? `<p class="owners">${owners.map((o) => `<b>${esc(o)}</b>`).join(" · ")} <span class="muted">home</span></p>` : ""}<div class="chips">${shown.map((d) => `<button type="button" class="device-chip" data-open="${esc(d.id)}"><b>${esc(d.label)}</b><span>${esc(deviceSub(d))}</span></button>`).join("")}
    ${more > 0 ? `<button type="button" class="device-chip more" data-tab="devices"><b>${more} more</b><span>all devices</span></button>` : ""}</div>`;
}

function findingsBlock(rep) {
  if (!rep) return `<p class="muted"><span class="spinner inline"></span> Checking for findings…</p>`;
  const list = rep.findings || [];
  if (!list.length) return `<p class="muted">${rep.learning ? "Still learning this network: checks that compare with history start after a day." : rep.scanned_at ? "Nothing needs a look." : "The first check is still running."}</p>`;
  const order = { high: 0, medium: 1, low: 2 };
  // The same sentence from several findings (a beacon that came back, a
  // container recreated with a new MAC) is one line, counted.
  const lines = new Map();
  for (const a of [...list].sort((a, b) => order[a.severity] - order[b.severity])) {
    const k = `${a.severity}\u0000${a.summary}`;
    const l = lines.get(k);
    if (l) l.n++;
    else lines.set(k, { a, n: 1 });
  }
  const all = [...lines.values()];
  const top = all.slice(0, 5);
  const rest = top.reduce((n, l) => n - l.n, list.length);
  return `<ul class="finds">${top.map(({ a, n }) => `<li><span class="badge sev-${esc(a.severity)}">${esc(a.severity)}</span> ${esc(a.summary)}${n > 1 ? ` <span class="muted">×${n}</span>` : ""}</li>`).join("")}</ul>
    ${rest > 0 ? `<p class="muted">and ${rest} more.</p>` : ""}
    <button type="button" data-home-findings>Review ${esc(plural(list.length, "finding"))} →</button>`;
}

// installBlock is how to connect a sensor to this server.
export function installBlock(origin) {
  const run = `NETGRAPH_TOKEN=<your ingest token> netgraph-sensor run -iface br-lan -server ${origin}`;
  const compose = `export NETGRAPH_TOKEN=<your ingest token>\ndocker compose -f deploy/compose/sidecar.yml up -d`;
  return `<ol class="steps">
    <li><b>On your router, or any Linux box that forwards your LAN,</b> run the sensor. It needs <code>CAP_NET_RAW</code>, and <code>-iface</code> is the interface your LAN is on.
      <div class="code"><pre>${esc(run)}</pre><button type="button" data-copy="${esc(run)}">Copy</button></div></li>
    <li><b>Or watch a Docker host</b> with the sidecar.
      <div class="code"><pre>${esc(compose)}</pre><button type="button" data-copy="${esc(compose)}">Copy</button></div></li>
    <li>The token is the one this server was started with (<code>NETGRAPH_TOKEN</code>).</li>
  </ol>`;
}

function firstRun(h, origin) {
  return `<div class="first-run">
    <h2>Welcome to netgraph</h2>
    <p>It shows what's on your network and what it talks to, as a map you can scrub through time. It only needs a sensor to tell it what it sees.</p>
    <div class="card">${installBlock(origin)}</div>
    <p class="waiting" role="status"><span class="spinner inline"></span> ${h.sensors.length ? `${esc(h.sensors[0].name)} has connected; waiting for its first packets…` : "Waiting for the first packets…"} This page updates by itself.</p>
    <p class="muted">Just looking around? <code>make demo</code> in a checkout serves a generated home network, no capture needed.</p>
  </div>`;
}

// homeHTML is the whole page. rep is the findings report, null until it arrives.
export function homeHTML(h, rep, { firstVisit, origin, links = 0, extra = "" }) {
  if (h.state === "no_data") return firstRun(h, origin);
  const [cls, icon, head, sub] = status(h);
  const s = h.summary_since;
  const quiet = h.sensors.filter((x) => x.quiet);
  return `<div class="home">
    <div class="home-status ${cls}" role="status"><span class="status-icon" aria-hidden="true">${icon}</span><b>${esc(head)}</b><span>${esc(sub)}</span></div>
    <div class="home-grid">
      <section class="card since" aria-labelledby="h-since">
        <header class="card-head"><h2 id="h-since">${esc(sinceTitle(h, firstVisit))}</h2>${firstVisit ? "" : `<button type="button" data-home-seen>Mark as seen</button>`}</header>
        <div class="stats">
          <div><b>${h.new_devices.length}</b><span>new ${h.new_devices.length === 1 ? "device" : "devices"}</span></div>
          <div><b>${rep ? (rep.findings || []).length : "…"}</b><span>open findings</span></div>
          <div><b>${esc(bytes(s?.bytes_out))}</b><span>sent</span></div>
          <div><b>${esc(bytes(s?.bytes_in))}</b><span>received</span></div>
        </div>
        ${h.new_devices.length ? `<h3>New devices</h3><ul class="new-devices">${h.new_devices.slice(0, 6).map((d) => `<li><button type="button" class="row-link" data-open="${esc(d.id)}"><b>${esc(d.label)}</b> <span class="muted">${esc(deviceSub(d))} · first seen ${esc(stamp(d.first_seen))}</span></button></li>`).join("")}</ul>` : ""}
        <h3>Findings</h3>
        ${findingsBlock(rep)}
      </section>
      ${links ? `<section class="card" aria-labelledby="h-links"><header class="card-head"><h2 id="h-links">${links === 1 ? "A device to confirm" : `${links} devices to confirm`}</h2><button type="button" data-tab="links">Review →</button></header>
        <p class="muted">${links === 1 ? "A private address looks like" : "Private addresses look like"} a device you already know.</p></section>` : ""}
      <section class="card" aria-labelledby="h-here">
        <header class="card-head"><h2 id="h-here">${h.state === "ok" ? "Here now" : "Here at the end of the data"}</h2><span class="muted">${h.active.length}</span></header>
        ${people(h.active)}
      </section>
      ${extra}
      <section class="card" aria-labelledby="h-busy">
        <header class="card-head"><h2 id="h-busy">Busiest in the last hour</h2></header>
        ${talkers(h.top_talkers)}
      </section>
      <section class="card wide" aria-labelledby="h-traffic">
        <header class="card-head"><h2 id="h-traffic">Traffic, last 24 hours</h2><button type="button" data-tab="graph">Open the map →</button></header>
        ${trafficChart(h.traffic)}
      </section>
      ${quiet.length ? `<section class="card" aria-labelledby="h-sensors"><header class="card-head"><h2 id="h-sensors">Quiet sensors</h2><button type="button" data-tab="sensors">Sensors →</button></header>
        <ul class="finds">${quiet.map((x) => `<li><b>${esc(x.name)}</b> <span class="muted">last heard ${esc(ago(h.now - x.last_seen))}</span></li>`).join("")}</ul></section>` : ""}
    </div>
  </div>`;
}
