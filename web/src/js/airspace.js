// The air: which channels have networks on them. Network names are chosen by whoever runs
// the network, including a neighbour or an attacker, so all of it goes through esc().
import { esc, ago } from "./util.js";

const plural = (n, one) => `${n} ${one}${n === 1 ? "" : "s"}`;
const nonOverlapping = [1, 6, 11];

// The least crowded of the three 2.4 GHz channels that don't overlap, counting what shares its air.
function quietest24(channels) {
  const score = (ch) => {
    const here = channels.find((c) => c.channel === ch);
    if (here) return here.networks + here.overlapping;
    return channels.filter((c) => Math.abs(c.channel - ch) < 5).reduce((sum, c) => sum + c.networks, 0);
  };
  return [...nonOverlapping].sort((a, b) => score(a) - score(b) || a - b)[0];
}

function band(name, channels) {
  const peak = Math.max(1, ...channels.map((c) => c.networks));
  const bars = channels.map((c) => {
    const tip = `Channel ${c.channel}: ${plural(c.networks, "network")}, ${plural(c.clients, "client")}${c.strongest ? `, loudest ${c.strongest} dBm` : ""}${c.overlapping ? `, overlapped by ${plural(c.overlapping, "network")} nearby` : ""}`;
    return `<li class="air-bar" title="${esc(tip)}"><span class="air-count">${c.networks}</span><span class="air-fill${c.overlapping ? " crowded" : ""}" style="height:${((c.networks / peak) * 100).toFixed(1)}%"></span><span class="air-channel">${c.channel}</span></li>`;
  }).join("");
  const advice = name === "2.4 GHz" ? `<p class="muted">Of the channels that don't overlap (1, 6, 11), <b>${quietest24(channels)}</b> has the fewest networks sharing it. A darker bar has neighbours close enough to share its air.</p>` : "";
  return `<section class="card"><h3>${esc(name)}</h3><ul class="air-bars" aria-label="${esc(`Networks per channel on ${name}`)}">${bars}</ul>${advice}</section>`;
}

const signalWords = (dbm) => {
  if (!dbm) return "";
  if (dbm >= -55) return "strong";
  if (dbm >= -70) return "good";
  if (dbm >= -80) return "weak";
  return "faint";
};

export function airspaceHTML(a) {
  if (!a.networks.length) {
    return `<p class="muted empty">No Wi-Fi heard in this window. This needs a sensor on a monitor-mode interface: see Deployment, under Wi-Fi.</p>`;
  }
  const bands = [...new Set(a.channels.map((c) => c.band))];
  const rogue = a.networks.filter((n) => n.rogue).length;
  const rows = a.networks.map((n) => `<tr class="${n.rogue ? "air-rogue" : ""}">
      <td>${n.ssid ? esc(n.ssid) : `<span class="muted">hidden</span>`}${n.rogue ? ` <span class="badge sev-high">unexpected</span>` : ""}</td>
      <td class="mono">${esc(n.bssid)}</td>
      <td>${n.security ? `<span class="badge">${esc(n.security)}</span>` : ""}</td>
      <td class="num">${esc(n.band || "")} ${n.channel || ""}</td>
      <td class="num">${n.signal ? `${n.signal} dBm <span class="muted">${signalWords(n.signal)}</span>` : ""}</td>
      <td class="num" title="${esc((n.clients || []).join(", "))}">${(n.clients || []).length}</td>
      <td class="muted">${esc(ago(Date.now() - n.last_seen))}</td>
    </tr>`).join("");
  return `<p>${plural(a.networks.length, "network")} on ${plural(a.channels.length, "channel")}${rogue ? `, <b>${rogue} unexpected</b>` : ""}.</p>
    <div class="air-bands">${bands.map((b) => band(b, a.channels.filter((c) => c.band === b))).join("")}</div>
    <table class="mini"><thead><tr><th>Network</th><th>BSSID</th><th>Security</th><th class="num">Channel</th><th class="num">Signal</th><th class="num">Clients</th><th>Heard</th></tr></thead><tbody>${rows}</tbody></table>
    <p class="muted">What a sensor heard from where it sits, not a survey. It counts networks rather than how busy each one is, and only sees channels a monitor-mode sensor visits.</p>`;
}
