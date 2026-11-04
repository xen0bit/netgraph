// One device's profile. Every value that came off the network goes through esc().
import { esc, bytes, stamp, ago, pad2 } from "./util.js";

// compare says how this week reads against the last, in words.
function compare(now, then, has) {
  if (!has) return "new this week";
  if (!then) return now ? "nothing the week before" : "same as the week before";
  const r = now / then;
  if (r >= 1.5) return `${r.toFixed(1)}× the week before`;
  if (r <= 0.67) return r < 0.1 ? "far below the week before" : `${Math.round(r * 100)}% of the week before`;
  return "about the same as the week before";
}

function hoursChart(hours) {
  const peak = Math.max(1, ...hours);
  const sum = hours.reduce((a, b) => a + b, 0);
  if (!sum) return `<p class="muted">Nothing this week.</p>`;
  const busiest = hours.indexOf(Math.max(...hours));
  return `<div class="tchart short" role="group" aria-label="${esc(`Traffic by hour of the day this week; busiest around ${pad2(busiest)}:00`)}">${hours.map((v, h) => {
    const tip = `${pad2(h)}:00 · ${bytes(v)} this week`;
    return `<span class="tbar still" title="${esc(tip)}"><span style="height:${v ? Math.max(3, (v / peak) * 100).toFixed(1) : 0}%"></span></span>`;
  }).join("")}</div><div class="taxis"><span>00:00</span><span>12:00</span><span>23:00</span></div>`;
}

// Fourteen slots whatever the data holds: a device seen for one day shows one
// bar among empty days, not one bar the width of the chart.
function daysChart(days, asOf) {
  if (!days.length) return `<p class="muted">Nothing in the last two weeks.</p>`;
  const total = (d) => d.bytes_in + d.bytes_out;
  const peak = Math.max(1, ...days.map(total));
  const label = (ms) => stamp(ms).slice(0, 10);
  const byDay = new Map(days.map((d) => [label(d.ts), d]));
  const slots = [];
  const day = new Date(asOf);
  day.setHours(12, 0, 0, 0); // noon: a daylight-saving day can't skip or repeat a date
  day.setDate(day.getDate() - 13);
  for (let i = 0; i < 14; i++) {
    const name = label(day.getTime());
    const d = byDay.get(name);
    if (d) {
      const tip = `${name} · ${bytes(total(d))} · ${d.flows} connections`;
      slots.push(`<button type="button" class="tbar" data-day="${d.ts}" title="${esc(tip)}" aria-label="${esc(tip)}"><span style="height:${Math.max(3, (total(d) / peak) * 100).toFixed(1)}%"></span></button>`);
    } else {
      slots.push(`<span class="tbar still" title="${esc(`${name} · nothing`)}"><span style="height:0"></span></span>`);
    }
    day.setDate(day.getDate() + 1);
  }
  return `<div class="tchart short" role="group" aria-label="Traffic per day, last two weeks">${slots.join("")}</div>
    <div class="taxis"><span>two weeks ago</span><span>${esc(label(asOf))}</span></div>`;
}

export function passportHTML(p) {
  const d = p.device, w = p.this_week, l = p.last_week;
  const total = (x) => x.bytes_in + x.bytes_out;
  const identity = [
    ["Vendor", d.randomized ? "private MAC (it changes; the vendor isn't known)" : d.vendor],
    ["MAC", d.mac],
    ["Addresses", (d.ips || []).join(", ")],
    ["Hostnames", (d.hostnames || []).join(", ")],
    ["Services", (d.services || []).join(", ")],
    ["Serves", (d.serves || []).join(", ")],
    ["Role", d.role],
    ["First seen", stamp(d.first_seen)],
    ["Last seen", `${stamp(d.last_seen)}, ${ago(Date.now() - d.last_seen)}`],
  ].filter(([, v]) => v);
  const segs = (p.story?.segments || []).slice(0, 12);
  return `<article class="passport">
    <header class="passport-head">
      <div><h2>${esc(d.label)}</h2>${d.user_label && d.auto_label ? `<div class="muted">also known as ${esc(d.auto_label)}</div>` : ""}</div>
      <div class="actions">
        <button type="button" data-pp-details>Details</button>
        <button type="button" data-pp-map>On the map</button>
        <button type="button" data-pp-follow>Follow in Recorder</button>
        <button type="button" data-pp-copy>Copy link</button>
      </div>
    </header>
    <div class="home-grid">
      <section class="card"><h3>Identity</h3><dl class="facts-list">${identity.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("")}</dl></section>
      <section class="card"><h3>This week</h3>
        <div class="stats three">
          <div><b>${esc(bytes(total(w)))}</b><span>${esc(compare(total(w), total(l), p.has_last_week))}</span></div>
          <div><b>${w.flows}</b><span>connections${p.has_last_week ? ` · ${esc(compare(w.flows, l.flows, true))}` : ""}</span></div>
          <div><b>${w.destinations}</b><span>destinations${p.has_last_week ? ` · ${p.new_destinations} new` : ""}</span></div>
        </div>
        <h3>When it's busy</h3>${hoursChart(p.hours)}
        <h3>Last two weeks</h3>${daysChart(p.days, p.as_of)}
      </section>
      <section class="card"><h3>What it talked to this week</h3>
        ${p.destinations.length ? `<table class="mini"><thead><tr><th>Name or address</th><th></th><th class="num">Conns</th><th class="num">Sent</th><th class="num">Received</th></tr></thead><tbody>
        ${p.destinations.map((x) => `<tr><td>${esc(x.key)}${x.new ? ` <span class="badge sev-low">new</span>` : ""}</td><td><span class="badge dir-${esc(x.direction)}">${esc(x.direction === "local" ? "lan" : x.direction)}</span></td><td class="num">${x.flows}</td><td class="num">${esc(bytes(x.bytes_out))}</td><td class="num">${esc(bytes(x.bytes_in))}</td></tr>`).join("")}
        </tbody></table>` : `<p class="muted">Nothing this week.</p>`}
      </section>
      <section class="card"><h3>Last 24 hours</h3>
        ${segs.length ? `<ul class="finds">${segs.map((s) => `<li><span class="badge">${esc(s.kind)}</span> ${esc(s.label)} <span class="muted">${esc(stamp(s.from).slice(11))}</span></li>`).join("")}</ul>` : `<p class="muted">Nothing recorded.</p>`}
      </section>
    </div>
    <p class="muted">Counted from hourly totals, so a week's edges are rounded to the hour. As of ${esc(stamp(p.as_of))}.</p>
  </article>`;
}
