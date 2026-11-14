// netgraph's own DNS server, when it runs (netgraph serve -dns-listen): its
// status and rules in Settings, and what it refused, on Home. Names come off
// the network, and go through esc().
import { esc, stamp } from "./util.js";

// blockedBy reads "rule:12" or "list:AdGuard DNS filter" as words.
export function blockedBy(by) {
  if (!by) return "";
  const [kind, ...rest] = by.split(":");
  const v = rest.join(":");
  return kind === "rule" ? `rule ${v}` : kind === "list" ? `list ${v}` : by;
}

const scopeName = (r, names) => r.scope === "all" ? "Everyone"
  : r.scope === "group" ? `Group ${r.scope_value}`
  : names[`device:${r.scope_value}`] || r.scope_value;

// settingsHTML is the DNS server's card: how to turn it on, or how it's
// doing and its rules.
export function settingsHTML(st, rules, { canEdit, names = {} }) {
  if (!st?.enabled) {
    return `<p>Off. With <code>-dns-listen :53</code> and <code>-dns-upstream-file</code> (a file of resolvers such as
      <code>tls://9.9.9.9#dns.quad9.net</code>), netgraph answers your network's lookups itself: it records every one,
      and refuses names a blocklist under Findings → Manage, or a rule here, blocks. It answers only private addresses unless
      <code>-dns-allow</code> says otherwise. Point your DHCP server's DNS option at this machine.</p>
      ${rules?.length ? `<p class="muted">${rules.length} rules are saved for when it runs.</p>` : ""}`;
  }
  const pct = st.queries ? Math.round((st.blocked / st.queries) * 100) : 0;
  const ups = (st.upstreams || []).map((u) => `<tr><td class="mono">${esc(u.name)}</td><td>${u.healthy ? "answering" : `<span class="badge sev-high">failing</span>`}</td>
    <td class="num">${u.answered}</td><td class="num">${u.failed}</td><td class="num">${u.latency_ms ? `${u.latency_ms.toFixed(1)} ms` : ""}</td></tr>`).join("");
  return `<div class="dns-numbers">
      <div><b>${st.queries}</b><span>lookups answered</span></div>
      <div><b>${st.blocked}</b><span>refused (${pct}%)</span></div>
      <div><b>${st.cache_hits}</b><span>from the cache</span></div>
      <div><b>${st.refused}</b><span>from outside, refused</span></div>
    </div>
    <p class="muted">Listening on ${esc((st.listen || []).join(", "))}. A blocked name is answered ${esc({ null: "0.0.0.0 and ::", nxdomain: "“no such name”", refused: "REFUSED" }[st.block_mode] || st.block_mode)}.
      ${st.rules} rules and ${st.list_entries} blocklist entries in force${st.rules_at ? `, read ${esc(stamp(st.rules_at))}` : ""}.</p>
    ${st.rules_error ? `<p class="badge sev-high">Can't read the rules: ${esc(st.rules_error)}</p>` : ""}
    <table class="mini"><thead><tr><th>Upstream</th><th></th><th class="num">Answered</th><th class="num">Failed</th><th class="num">Takes</th></tr></thead><tbody>${ups}</tbody></table>
    ${rulesHTML(rules, { canEdit, names })}`;
}

export function rulesHTML(rules, { canEdit, names = {} }) {
  const rows = (rules || []).map((r) => `<tr><td>${esc(scopeName(r, names))}</td>
    <td>${r.action === "block" ? `<span class="badge sev-high">block</span>` : `<span class="badge">allow</span>`}</td>
    <td class="mono">${r.pattern === "*" ? "every name" : esc(r.pattern)}</td><td class="muted">${esc(r.note || "")}</td>
    <td>${canEdit ? `<button type="button" data-dns-delete="${r.id}" aria-label="Delete the rule for ${esc(r.pattern)}">Delete</button>` : ""}</td></tr>`).join("");
  return `<h3>Rules</h3>
    <p class="muted">A name covers its subdomains. The most specific say wins: a device's own rules, then its groups', then everyone's, then the blocklists. Allow beats block within one.</p>
    ${rows ? `<table class="mini"><thead><tr><th>For</th><th></th><th>Name</th><th>Why</th><th></th></tr></thead><tbody>${rows}</tbody></table>` : `<p class="muted">No rules yet: blocklists alone decide.</p>`}
    ${canEdit ? `<form class="dns-add" data-dns-add>
      <select name="action" aria-label="Block or allow"><option value="block">Block</option><option value="allow">Allow</option></select>
      <input name="pattern" placeholder="ads.example.com" aria-label="Name" required maxlength="253">
      <select name="scope" aria-label="For whom"><option value="all">for everyone</option><option value="device">for one device (MAC)</option><option value="group">for a group</option></select>
      <input name="scope_value" placeholder="MAC or group" aria-label="Device MAC or group" maxlength="64">
      <input name="note" placeholder="why (optional)" aria-label="Why" maxlength="200">
      <button type="submit">Add</button></form>` : ""}`;
}

// homeCard is Home's line on the DNS server: what it refused in the day.
export function homeCard(st) {
  if (!st) return "";
  const top = (st.top_blocked || []).slice(0, 5);
  return `<section class="card"><h2>Lookups blocked</h2>
    <p class="big"><b>${st.blocked}</b> of ${st.queries} lookups in the last day</p>
    ${top.length ? `<ul class="tight">${top.map((n) => `<li><a data-open="${esc(`domain:${n.name}`)}">${esc(n.name)}</a> <span class="muted">×${n.count}</span></li>`).join("")}</ul>` : `<p class="muted">Nothing was blocked.</p>`}
    <button type="button" data-tab="dns">See the lookups →</button></section>`;
}

