// The findings inbox: what the checks have found, and what's been decided about it.
// Every value that came off the network goes through esc().
import { esc, stamp, ago } from "./util.js";

const statusNames = { new: "New", seen: "Seen", acknowledged: "Acknowledged", resolved: "Resolved", dismissed: "Fine" };
const kindName = (k) => k.replaceAll("_", " ");

function row(f) {
  const back = f.recurrences ? ` <span class="badge sev-low" title="${esc(`Came back ${f.recurrences} times after being resolved`)}">back</span>` : "";
  return `<li class="finding ${f.status === "new" ? "unread" : ""}">
    <button type="button" class="row-link" data-finding="${f.id}">
      <span class="badge sev-${esc(f.severity)}">${esc(f.severity)}</span>
      <span class="finding-what">${esc(f.summary)}${back}</span>
      <span class="muted finding-meta">${esc(kindName(f.kind))} · ${esc(statusNames[f.status] || f.status)}${f.auto_resolved ? " (went quiet)" : ""} · ${esc(ago(Date.now() - f.last_seen))}${f.occurrences > 1 ? ` · ${f.occurrences} times` : ""}</span>
    </button></li>`;
}

export function findingsHTML(l, status) {
  const n = l.counts || {};
  const open = (n.new || 0) + (n.seen || 0) + (n.acknowledged || 0);
  const tabs = [["open", `Open ${open}`], ["resolved", `Resolved ${n.resolved || 0}`], ["dismissed", `Fine ${n.dismissed || 0}`], ["", "All"]];
  const head = `<div class="table-tools finding-tools">
    <div class="segmented" role="group" aria-label="Which findings">${tabs.map(([v, t]) => `<button type="button" data-findings-status="${v}" aria-pressed="${status === v}">${esc(t)}</button>`).join("")}</div>
    <span class="spacer"></span>
    ${n.new ? `<button type="button" data-findings-seen>Mark ${n.new} as seen</button>` : ""}
    <span class="muted">${l.scanned_at ? `checked ${esc(ago(Date.now() - l.scanned_at))}` : "first check running"}</span>
  </div>${l.learning ? `<p class="muted">Still learning this network: checks that compare with history start after a day.</p>` : ""}`;
  if (!l.findings.length) {
    return `${head}<p class="muted empty">${status === "open" ? (l.scanned_at ? "Nothing needs a look." : "Nothing yet. The first check runs when the server starts, then every five minutes.") : "None."}</p>`;
  }
  const byID = new Map(l.findings.map((f) => [f.id, f]));
  const grouped = new Set();
  const stories = (l.groups || []).map((g) => {
    const items = g.ids.map((id) => byID.get(id)).filter(Boolean);
    items.forEach((f) => grouped.add(f.id));
    return { ts: g.to, html: `<li class="finding-group"><details open><summary><span class="badge sev-${esc(g.severity)}">${esc(g.severity)}</span> <b>${esc(g.device_name || g.device)}</b> <span class="muted">${items.length} findings close together, ${esc(stamp(g.from))}</span></summary><ul class="findings">${items.map(row).join("")}</ul></details></li>` };
  });
  const rest = l.findings.filter((f) => !grouped.has(f.id)).map((f) => ({ ts: f.last_seen, html: row(f) }));
  const all = [...stories, ...rest].sort((a, b) => b.ts - a.ts);
  return `${head}<ul class="findings">${all.map((x) => x.html).join("")}</ul>`;
}

// findingDetail is one finding, explained, in the details panel.
export function findingDetail(f) {
  const ev = Object.entries(f.evidence || {}).sort(([a], [b]) => a.localeCompare(b));
  const closed = f.status === "resolved" || f.status === "dismissed";
  return `<h2>${esc(f.summary)}</h2>
    <p><span class="badge sev-${esc(f.severity)}">${esc(f.severity)}</span> <span class="badge">${esc(kindName(f.kind))}</span> <span class="badge">${esc(statusNames[f.status] || f.status)}</span></p>
    <h3>Why this fired</h3><p>${esc(f.why)}</p>
    ${f.usual ? `<h3>Is this normal here?</h3><p>${esc(f.usual)}</p>` : ""}
    <h3>What you could do</h3><p>${esc(f.advice)}</p>
    <div class="finding-actions">
      ${closed ? `<button type="button" data-fstatus="new">Reopen</button>` : `<button type="button" data-fstatus="acknowledged"${f.status === "acknowledged" ? " disabled" : ""}>Acknowledge</button><button type="button" data-fstatus="resolved">Resolve</button>`}
      ${f.status === "dismissed" ? "" : `<button type="button" data-ffine title="Stops this being reported, for this device and this thing. Findings › Anomalies lists these, to undo.">This is fine</button>`}
      ${f.device ? `<button type="button" data-fdevice="${esc(f.device)}">The device</button>` : ""}
      <button type="button" data-fmoment>See that moment</button>
    </div>
    <h3>Note</h3><form class="finding-note"><input name="note" maxlength="500" value="${esc(f.note)}" aria-label="Note"><button type="submit">Save</button></form>
    <dl><dt>first seen</dt><dd>${esc(stamp(f.first_seen))}</dd><dt>last seen</dt><dd>${esc(stamp(f.last_seen))}</dd><dt>times</dt><dd>${f.occurrences}</dd>${f.recurrences ? `<dt>came back</dt><dd>${f.recurrences}</dd>` : ""}
    ${ev.map(([k, v]) => `<dt>${esc(k.replaceAll("_", " "))}</dt><dd>${esc(v)}</dd>`).join("")}</dl>`;
}
