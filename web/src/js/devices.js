// What the Devices area shows beyond its table: what a device is, when devices
// were seen, and which private addresses may be known devices. Every value that
// came off the network goes through esc().
import { esc, stamp, clock, units } from "./util.js";

// A type's server name is the map's icon name; these are the words for people.
export const typeNames = { router: "Router", ap: "Access point", switch: "Network switch", phone: "Phone", tablet: "Tablet", laptop: "Computer", tv: "TV or streamer", speaker: "Speaker", printer: "Printer", camera: "Camera", nas: "Storage (NAS)", server: "Server", game: "Game console", iot: "Smart home" };
export const typeName = (t) => typeNames[t] || (t ? t : "Unknown");

const signalNames = { vendor: "maker", hostname: "name", service: "announces", model: "model", fingerprint: "DHCP or TLS fingerprint", user_agent: "browser", upnp: "UPnP", port: "answers on", role: "role" };

export function typeBadge(d) {
  if (!d.type) return `<span class="muted">unknown</span>`;
  const how = d.user_type ? "you said" : d.type_confidence === "high" ? "" : `${d.type_confidence || "low"} confidence`;
  return `${esc(typeName(d.type))}${how ? ` <span class="sub-inline" title="${esc(d.user_type ? "Set by a person" : "How sure the classifier is")}">${esc(how)}</span>` : ""}`;
}

// typeWhy is the reasoning: what was seen, and what each thing points to.
export function typeWhy(d) {
  if (d.user_type) return `<p class="muted">You set this${d.type_why?.length ? "; the signals below are what the classifier saw." : "."}</p>${whyList(d)}`;
  if (!d.type_why?.length) return `<p class="muted">Nothing it said about itself points to a type.</p>`;
  return `<p class="muted">Devices can claim anything, so this is a judgement, not a fact.</p>${whyList(d)}`;
}

function whyList(d) {
  if (!d.type_why?.length) return "";
  return `<ul class="why">${d.type_why.map((r) => `<li><span class="muted">${esc(signalNames[r.signal] || r.signal)}</span> ${esc(r.value)} <span class="muted">→ ${esc(typeName(r.says))}${r.weight >= 8 ? ", strongly" : ""}</span></li>`).join("")}</ul>`;
}

// profileForm is where a person overrules the classifier and says whose it is.
export function profileForm(d, attrs) {
  const user = attrs?.user_type || "";
  const opts = Object.entries(typeNames).map(([k, v]) => `<option value="${esc(k)}"${k === user ? " selected" : ""}>${esc(v)}</option>`).join("");
  const auto = d?.type && !d.user_type ? ` (${typeName(d.type)})` : "";
  return `<form class="profile" autocomplete="off">
    <label>Type <select name="type"><option value="">Automatic${esc(auto)}</option>${opts}</select></label>
    <label>Owner <input name="owner" maxlength="64" value="${esc(attrs?.owner || "")}" placeholder="Alice"></label>
    <label>Groups <input name="groups" maxlength="200" value="${esc((attrs?.groups || "").replaceAll(",", " "))}" placeholder="iot guests"></label>
    <button type="submit">Save</button><output class="muted"></output>
  </form>`;
}

// presenceHTML draws when each device moved traffic, grouped by owner.
export function presenceHTML(p) {
  if (!p.devices.length) return `<p class="muted empty">No device moved traffic in this window.</p>`;
  const span = p.to - p.from;
  const pct = (ms) => ((ms - p.from) / span) * 100;
  const short = (ms) => (span > units.d ? stamp(ms).slice(5, 16) : clock(ms));
  const groups = new Map();
  for (const d of p.devices) {
    const k = d.owner || "";
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(d);
  }
  const named = [...groups.entries()].sort(([a], [b]) => (!a) - (!b) || a.localeCompare(b));
  const rows = named.map(([owner, list]) => `${owner || groups.size > 1 ? `<h3 class="presence-owner">${owner ? esc(owner) : "No owner"}</h3>` : ""}${list.map((d) => `<div class="presence-row">
    <button type="button" class="row-link" data-open="${esc(d.id)}"><b>${esc(d.label)}</b>${d.type ? ` <span class="muted">${esc(typeName(d.type))}</span>` : ""}</button>
    <div class="presence-track" role="img" aria-label="${esc(`${d.label}: ${d.intervals.map(([a, b]) => `${short(a)} to ${short(b)}`).join(", ")}`)}">${d.intervals.map(([a, b]) => `<span title="${esc(`${short(a)} to ${short(b)}`)}" style="left:${pct(a).toFixed(2)}%;width:${(pct(b) - pct(a)).toFixed(2)}%"></span>`).join("")}</div>
  </div>`).join("")}`).join("");
  return `<div class="presence">
    <div class="presence-row axis"><span></span><div class="taxis"><span>${esc(short(p.from))}</span><span>${esc(short(p.to))}</span></div></div>
    ${rows}
    <p class="muted">“Seen” means it moved traffic, from ${p.precision === "minute" ? "per-minute" : "hourly"} totals: a quiet gap under ${Math.round(p.gap / units.m)} minutes doesn't count, and a phone asleep on the network doesn't show. Multicast and broadcast chatter is left out.</p>
  </div>`;
}

const reasonNames = { hostname: "same name", service: "announces the same service", fingerprint: "same fingerprint", user_agent: "same browser" };

// linksHTML asks about each suggestion; it never decides.
export function linksHTML(links) {
  if (!links.length) return `<div class="first-run"><h2>Nothing to ask</h2><p class="muted">Phones and laptops change to a private address on some networks. When one looks like a device already known, by name or announced service and never online alongside it, it's asked about here.</p></div>`;
  return `<div class="links">${links.map((l) => `<section class="card">
    <h2>Is <em>${esc(l.device.label)}</em> also <em>${esc(l.same.label)}</em>?</h2>
    <p class="muted">${esc(l.device.mac)}, first seen ${esc(stamp(l.device.first_seen))}, may be ${esc(l.same.mac)}, last seen ${esc(stamp(l.same.last_seen))}. They were never online together. ${l.confidence === "high" ? "Several things match." : "Only one strong thing matches."}</p>
    <ul class="why">${l.reasons.map((r) => `<li><span class="muted">${esc(reasonNames[r.signal] || r.signal)}</span> ${esc(r.value)}</li>`).join("")}</ul>
    <div class="actions"><button type="button" data-link="same" data-mac="${esc(l.device.mac)}" data-same="${esc(l.same.mac)}">Yes, the same device</button>
    <button type="button" data-link="different" data-mac="${esc(l.device.mac)}" data-same="${esc(l.same.mac)}">No</button></div>
    <p class="muted">Yes links them and copies the name, owner and groups across. History stays under each address, and a passport's “Undo the link” takes it back.</p>
  </section>`).join("")}</div>`;
}

const verdictMark = { good: ["ok", "●"], unknown: ["info", "■"], slow_local: ["warn", "▲"], slow_upstream: ["warn", "▲"], lossy: ["warn", "▲"], outage: ["warn", "▲"] };
const ms = (v, samples) => (samples ? `${v < 10 ? v.toFixed(1) : Math.round(v)} ms` : "no data");

// qualityHTML is how the network is doing, in words first.
export function qualityHTML(q) {
  const [cls, icon] = verdictMark[q.verdict] || verdictMark.unknown;
  const peak = Math.max(1, ...q.series.map((p) => p.wan_p50_ms));
  const chart = q.series.length ? `<div class="tchart short" role="group" aria-label="${esc(`Delay upstream over the window, at most ${Math.round(peak)} ms`)}">${q.series.map((p) => {
    const tip = `${stamp(p.ts)} · upstream ${ms(p.wan_p50_ms, p.wan_p50_ms)} · here ${ms(p.lan_p50_ms, p.lan_p50_ms)} · ${p.retrans_pct.toFixed(1)}% sent again`;
    return `<span class="tbar still" title="${esc(tip)}"><span style="height:${p.wan_p50_ms ? Math.max(3, (p.wan_p50_ms / peak) * 100).toFixed(1) : 0}%"></span></span>`;
  }).join("")}</div><div class="taxis"><span>${esc(stamp(q.from))}</span><span>at most ${Math.round(peak)} ms</span><span>${esc(stamp(q.to))}</span></div>` : `<p class="muted">No handshakes in this window.</p>`;
  return `<div class="home">
    <div class="home-status ${cls}" role="status"><span class="status-icon" aria-hidden="true">${icon}</span><b>${esc(q.summary)}</b></div>
    <div class="home-grid">
      <section class="card"><h3>In numbers</h3><div class="stats">
        <div><b>${esc(ms(q.wan.p50_ms, q.wan.samples))}</b><span>upstream${q.usual.samples ? `, usually ${esc(ms(q.usual.p50_ms, q.usual.samples))}` : ""}</span></div>
        <div><b>${esc(ms(q.lan.p50_ms, q.lan.samples))}</b><span>to devices here</span></div>
        <div><b>${q.retrans_pct.toFixed(1)}%</b><span>sent again</span></div>
        <div><b>${esc(ms(q.dns.p50_ms, q.dns.samples))}</b><span>DNS${q.dns_timeouts ? `, ${q.dns_timeouts} unanswered` : ""}</span></div>
      </div>
      ${q.outages.length ? `<h3>Outages</h3><ul class="finds">${q.outages.map((o) => `<li>${esc(stamp(o.from))} to ${esc(stamp(o.to).slice(11))} <span class="muted">${o.attempts} connections unanswered</span></li>`).join("")}</ul>` : ""}
      <h3>Upstream over the window</h3>${chart}</section>
      <section class="card"><h3>By device, slowest link first</h3>
      ${q.devices.length ? `<table class="mini"><thead><tr><th>Device</th><th class="num">Here</th><th class="num">Upstream</th><th class="num">Sent again</th></tr></thead><tbody>${q.devices.slice(0, 20).map((d) => `<tr data-open="${esc(d.id)}"><td>${esc(d.label)}</td><td class="num">${esc(ms(d.lan.p50_ms, d.lan.samples))}</td><td class="num">${esc(ms(d.wan.p50_ms, d.wan.samples))}</td><td class="num">${d.retrans_pct.toFixed(1)}%</td></tr>`).join("")}</tbody></table>` : `<p class="muted">Nothing measured.</p>`}</section>
    </div>
    ${(q.gaps || []).map((g) => `<p class="muted">${esc(g)}</p>`).join("")}
    <p class="muted">Measured from TCP handshakes and retransmits as they pass the sensor. This is delay and loss, not speed. From a sensor on the router, "upstream" and "here" are the two sides of it; elsewhere, they mean less.</p>
  </div>`;
}
