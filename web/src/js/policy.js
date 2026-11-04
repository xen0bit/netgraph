// The policy builder. A draft lives in this browser; nothing here changes the network, and
// the server's only part is to simulate it and write it out. Every value may have come off
// the network (a device's label, a site's name), so all of it goes through esc().
import { esc } from "./util.js";

export const emptyPolicy = () => ({
  version: 1,
  zones: [],
  defaults: { egress: "allow", ingress: "allow", intra_zone: "allow", dns: "allow" },
  rules: [],
  dns: { block: [], allow: [] },
});

const KEY = "netgraph.policy.draft";

export function loadDraft(store) {
  try {
    const p = JSON.parse(store.get(KEY) || "null");
    if (p && Array.isArray(p.rules) && Array.isArray(p.zones) && p.defaults) return { ...emptyPolicy(), ...p };
  } catch { /* an unreadable draft is no draft */ }
  return emptyPolicy();
}

export const saveDraft = (store, p) => store.set(KEY, JSON.stringify(p));

const zoneFor = (p, deviceID) => {
  const found = p.zones.find((z) => z.devices.length === 1 && z.devices[0] === deviceID);
  if (found) return found.name;
  let name = `device-${deviceID.slice("device:".length).replaceAll(":", "")}`;
  while (p.zones.some((z) => z.name === name)) name += "-";
  p.zones.push({ name, devices: [deviceID] });
  return name;
};

// A map node as a rule's selector. A device is selected through a zone of its own.
function selectorFor(p, id) {
  const i = id.indexOf(":");
  const kind = id.slice(0, i), key = id.slice(i + 1);
  if (kind === "device") return `zone:${zoneFor(p, id)}`;
  if (["site", "domain", "ip", "asn", "country"].includes(kind)) return `${kind}:${key}`;
  return null; // never "any": denying one thing mustn't quietly deny everything
}

// addEdge makes a rule from a connection on the map, ahead of the rules before: the first to
// match decides, so the latest click wins. Asking again about the same two replaces the rule.
// It returns null, changing nothing, if a rule can't name one of the ends.
export function addEdge(p, edge, action, name) {
  const kinds = ["device", "site", "domain", "ip", "asn", "country"];
  if (![edge.from, edge.to].every((id) => kinds.includes(id.slice(0, id.indexOf(":"))))) return null;
  const from = selectorFor(p, edge.from), to = selectorFor(p, edge.to);
  p.rules = p.rules.filter((r) => !(r.from === from && r.to === to));
  p.rules.unshift({ name: `${action} ${name(edge.from)} to ${name(edge.to)}`, from, to, ports: [], action });
  return p;
}

const selectOf = (name, value, options) => `<select data-p="${esc(name)}" aria-label="${esc(name)}">${options.map(([v, t]) => `<option value="${esc(v)}" ${v === value ? "selected" : ""}>${esc(t)}</option>`).join("")}</select>`;
const actions = [["allow", "Allow"], ["deny", "Deny"]];

function ruleRow(r, i, count) {
  return `<tr data-rule="${i}">
    <td><input data-r="name" aria-label="Rule name" value="${esc(r.name)}"></td>
    <td><input data-r="from" aria-label="From" value="${esc(r.from)}" spellcheck="false"></td>
    <td><input data-r="to" aria-label="To" value="${esc(r.to)}" spellcheck="false"></td>
    <td><input data-r="ports" aria-label="Ports" value="${esc((r.ports || []).join(", "))}" placeholder="any" spellcheck="false"></td>
    <td>${selectOf("action", r.action, actions).replace('data-p="action"', 'data-r="action"')}</td>
    <td class="policy-row-tools">
      <button type="button" data-rule-up title="Earlier: the first to match decides" ${i === 0 ? "disabled" : ""} aria-label="Move up">↑</button>
      <button type="button" data-rule-down title="Later" ${i === count - 1 ? "disabled" : ""} aria-label="Move down">↓</button>
      <button type="button" data-rule-del title="Remove this rule" aria-label="Remove">✕</button>
    </td>
  </tr>`;
}

export function policyHTML(p, devices) {
  const d = p.defaults;
  const rows = p.rules.map((r, i) => ruleRow(r, i, p.rules.length)).join("");
  const options = devices.map((x) => `<option value="${esc(x.id)}">${esc(x.label)}${x.ips?.length ? ` (${esc(x.ips[0])})` : ""}</option>`).join("");
  return `<p class="muted">Try out a firewall policy against what really happened in this window. This changes nothing: the draft lives in this browser, and you apply any export yourself. Add rules here, or with Allow and Deny on any connection on the map.</p>
    <section class="card">
      <h3>Learn from a device</h3>
      <p class="muted">Proposes the least it needs: what it did in the last two weeks is allowed, and the rest denied.</p>
      <form id="policy-learn" class="policy-line"><select name="device" aria-label="Device" required><option value="">Choose a device</option>${options}</select>
      <button type="submit">Learn</button> <button type="button" data-policy-clear>Start over</button></form>
      <div id="policy-gaps"></div>
    </section>
    <section class="card">
      <h3>Rules</h3>
      ${rows ? `<table class="mini policy-rules"><thead><tr><th>Name</th><th>From</th><th>To</th><th>Ports</th><th>Action</th><th></th></tr></thead><tbody>${rows}</tbody></table>` : `<p class="muted">No rules yet.</p>`}
      <p><button type="button" data-rule-add>Add a rule</button> <span class="muted">The first rule to match decides.</span></p>
      <div class="policy-line">
        <label>Otherwise, leaving a zone ${selectOf("egress", d.egress, actions)}</label>
        <label>entering one ${selectOf("ingress", d.ingress, actions)}</label>
        <label>within one ${selectOf("intra_zone", d.intra_zone, actions)}</label>
      </div>
      <p class="muted">${p.zones.length ? `${p.zones.length} ${p.zones.length === 1 ? "zone" : "zones"}. Devices in none aren't affected, and show as unknown below.` : "No zones yet: nothing is affected until a rule names a device."}</p>
    </section>
    <section class="card" aria-live="polite"><h3>What this would do</h3><div id="policy-impact" class="muted">Working it out…</div></section>
    <section class="card">
      <h3>Export</h3>
      <p class="muted">Writes configuration for you to read and apply. netgraph never touches a firewall.</p>
      <div class="policy-line">${selectOf("format", "nftables", [["nftables", "nftables"], ["openwrt", "OpenWrt (fw4)"], ["opnsense", "OPNsense"]])}
        <button type="button" data-policy-export>Generate</button> <button type="button" data-policy-download hidden>Download</button></div>
      <div id="policy-warnings"></div>
      <textarea id="policy-config" readonly hidden rows="16" spellcheck="false" aria-label="Generated configuration"></textarea>
    </section>`;
}

// impactHTML says what a simulation found. The What-if dialog uses it too.
export function impactHTML(r) {
  const s = r.summary || {};
  const line = (x) => `<li><b>${esc(x.device_name || "unknown device")}</b> → ${esc(x.destination || "?")} <span class="mono">${esc(x.port || "")}</span> <span class="muted">${esc(x.reason || "")}${x.rule ? ` (${esc(x.rule)})` : ""}</span></li>`;
  return `<p><b>${s.blocked || 0}</b> blocked (<b>${s.essential || 0}</b> essential), <b>${s.lookups || 0}</b> lookups blocked, <b>${s.unknown || 0}</b> unknown, <b>${s.unchanged || 0}</b> unchanged.</p>
    ${(r.essential || []).length ? `<h3>Essential dependencies</h3><ul>${r.essential.map(line).join("")}</ul>` : ""}
    ${(r.blocked || []).length ? `<h3>Would be blocked</h3><ul>${r.blocked.slice(0, 100).map(line).join("")}</ul>` : ""}
    ${(r.unknown || []).length ? `<h3>Unknown</h3><ul>${r.unknown.slice(0, 50).map(line).join("")}</ul>` : ""}
    ${(r.gaps || []).map((g) => `<p class="muted">gap: ${esc(g)}</p>`).join("")}`;
}

// readRow takes an edited row back into its rule.
export function readRule(tr) {
  const v = (k) => tr.querySelector(`[data-r="${k}"]`).value.trim();
  return { name: v("name"), from: v("from"), to: v("to"), ports: v("ports").split(",").map((x) => x.trim()).filter(Boolean), action: v("action") };
}
