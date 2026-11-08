// The Processes view: every program a host agent reported in the window,
// what it connected to and accepted, who started it, and the bytes of the
// sensor's connections matched to it. Command lines and paths come from the
// hosts and peers off the network: everything goes through esc().
import { esc, bytes, stamp } from "./util.js";

const badge = (t, cls = "") => `<span class="badge ${esc(cls)}">${esc(t)}</span>`;
const list = (xs) => (xs || []).map((x) => `<div class="mono">${esc(x)}</div>`).join("");

// processesSpec is the table's columns; when formats a time as the other
// tables do.
export function processesSpec(when) {
  return {
    cols: ["Program", "Host", "PIDs", "Command line", "Started by", "Conns", "Talks to", "Serves", "Sent", "Received", "Last seen"],
    titles: {
      1: "The host agent that reported it, and the device the sensor saw it on",
      5: "The agent's sockets: out, in, and local (both ends on this host, which no sensor sees)",
      6: "What it connected to, busiest first", 7: "Ports it accepted connections on",
      8: "Bytes it sent, in the sensor's connections matched to it", 9: "Bytes it received, likewise",
    },
    num: [5, 8, 9],
    row: (p) => [
      `<b>${esc(p.name)}</b>${p.path ? `<div class="sub mono">${esc(p.path)}</div>` : ""}`,
      esc(p.agent) + (p.device_name || p.device ? `<div class="sub">${esc(p.device_name || p.device)}</div>` : ""),
      `<span class="mono">${(p.pids || []).slice(0, 3).map(Number).join(", ")}${(p.pids || []).length > 3 ? ` +${p.pids.length - 3}` : ""}</span>`,
      (p.cmdlines || []).slice(0, 2).map((c) => `<div class="mono sub">${esc(c.replace(/^pid \d+: /, ""))}</div>`).join(""),
      esc(p.started_by),
      `${Number(p.connections)}<div class="sub">${[p.out ? `${Number(p.out)} out` : "", p.in ? `${Number(p.in)} in` : "", p.local ? `${Number(p.local)} local` : ""].filter(Boolean).join(" · ")}</div>`,
      (p.peers || []).slice(0, 3).map((x) => `<div class="mono">${esc(x)}</div>`).join(""),
      (p.serves || []).map((x) => badge(x, "dir-in")).join(""),
      p.flows ? bytes(p.bytes_out) : "", p.flows ? bytes(p.bytes_in) : "", when(p.last_seen),
    ],
    keys: [(p) => p.name, (p) => p.agent + " " + (p.device_name || ""), (p) => p.pids?.[0], (p) => p.cmdlines?.[0], (p) => p.started_by,
      (p) => p.connections, (p) => p.peers?.[0], (p) => p.serves?.[0], (p) => p.bytes_out, (p) => p.bytes_in, (p) => p.last_seen],
    id: (p) => p.id || `program:${p.agent}/${p.name}`,
  };
}

// programDetail is the panel for a program no sensor connection was matched
// to (only loopback, say), so it has no device and no map node.
export function programDetail(p) {
  return `<h2>${esc(p.name)}</h2>
    <p>A program the host agent <b>${esc(p.agent)}</b> reported. No sensor saw its connections (they may all be on this host's loopback), so it is not on the map.</p>
    <dl>
      <dt>first seen</dt><dd>${stamp(p.first_seen)}</dd><dt>last seen</dt><dd>${stamp(p.last_seen)}</dd>
      ${p.path ? `<dt>path</dt><dd class="mono">${esc(p.path)}</dd>` : ""}
      ${p.code_id ? `<dt>code_id</dt><dd class="mono">${esc(p.code_id)}</dd>` : ""}
      ${p.pids?.length ? `<dt>pids</dt><dd class="mono">${p.pids.map(Number).join(", ")}</dd>` : ""}
      ${p.cmdlines?.length ? `<dt>cmdline</dt><dd>${list(p.cmdlines)}</dd>` : ""}
      ${p.started_by ? `<dt>started by</dt><dd>${esc(p.started_by)}</dd>` : ""}
      <dt>connections</dt><dd>${Number(p.connections)} (${Number(p.out)} out, ${Number(p.in)} in, ${Number(p.local)} local)</dd>
      ${p.peers?.length ? `<dt>talks to</dt><dd>${list(p.peers)}</dd>` : ""}
      ${p.serves?.length ? `<dt>serves</dt><dd>${list(p.serves)}</dd>` : ""}
    </dl>`;
}
