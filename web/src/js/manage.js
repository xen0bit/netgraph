// The management view for saved policies, blocklists, profiles, decisions and
// audits. Everything here is server configuration; traffic history stays in
// the other views.
import { esc } from "./util.js";

const badge = (text, cls = "") => `<span class="badge ${esc(cls)}">${esc(text)}</span>`;
const when = (ms) => (ms ? new Date(ms).toLocaleString() : "never");

export function manageHTML(d) {
  const policies = d.policies || [];
  const lists = d.blocklists || [];
  const profiles = d.profiles || [];
  const triggers = d.triggers || [];
  const decisions = d.decisions || [];
  const audit = d.audit || { findings: [], summary: {} };

  const policyRows = policies.map((p) => `<tr>
    <td class="mono">${esc(p.id)}</td><td>${esc(p.name)}</td><td>v${p.version} ${esc(p.mode)}</td>
    <td>${p.rules}</td><td>${p.active ? badge("active", "ok") : ""}</td>
    <td><button type="button" data-policy-activate="${esc(p.id)}">Activate</button>
        <button type="button" data-policy-delete="${esc(p.id)}">Delete</button></td>
  </tr>`).join("");

  const listRows = lists.map((b) => `<tr>
    <td>${esc(b.name)}</td><td class="mono">${esc(b.format)}</td><td>${b.entry_count}</td>
    <td>${b.enabled ? badge("enabled", "ok") : badge("disabled")}</td>
    <td>${esc(b.last_error || when(b.last_success))}</td>
    <td><button type="button" data-blocklist-update="${b.id}">Update</button>
        <button type="button" data-blocklist-delete="${b.id}">Delete</button></td>
  </tr>`).join("");

  const profileRows = profiles.map((p) => `<tr>
    <td>${esc(p.name)}</td><td>${esc(p.mode)}</td><td>${p.is_default ? badge("default") : ""}</td>
    <td>${p.active ? badge("active", "ok") : ""}</td>
    <td><button type="button" data-profile-activate="${p.id}">Activate</button>
        <button type="button" data-profile-delete="${p.id}">Delete</button></td>
  </tr>`).join("");

  const triggerRows = triggers.map((t) => `<tr>
    <td>${esc(t.profile_name || t.profile_id)}</td><td class="mono">${esc(t.signature)}</td>
    <td>${esc(t.action)} ${t.enabled ? "" : badge("off")}</td><td>${when(t.last_triggered)}</td>
    <td><button type="button" data-trigger-delete="${t.id}">Delete</button></td>
  </tr>`).join("");

  const decisionRows = decisions.map((x) => `<tr>
    <td>${when(x.ts)}</td><td>${esc(x.device_name || x.device)}</td><td>${esc(x.remote)}</td>
    <td class="mono">${esc(x.port)}</td><td>${badge(x.action)}</td><td>${esc(x.rule_name || "")}</td>
    <td><button type="button" data-decision-allow="${x.id}">Allow</button>
        <button type="button" data-decision-deny="${x.id}">Deny</button>
        <button type="button" data-decision-rule="${x.id}">Rule</button></td>
  </tr>`).join("");

  const auditRows = (audit.findings || []).map((f) => `<tr>
    <td>${esc(f.rule)}</td><td>${badge(f.kind, f.severity === "high" ? "err" : "")}</td>
    <td>${esc(f.detail)}</td></tr>`).join("");

  return `<p class="muted">Saved configuration and the passive decision queue. Nothing here enforces traffic; it records what the active policy would do and what an operator decides.</p>
  <section class="card"><h3>Saved policies</h3>
    ${policyRows ? `<table class="mini"><thead><tr><th>ID</th><th>Name</th><th>Version</th><th>Rules</th><th></th><th></th></tr></thead><tbody>${policyRows}</tbody></table>` : `<p class="muted">No saved policies yet. Use <b>Policy</b> to draft one and export it.</p>`}
    <p><label>Import a policy JSON here: <input type="file" id="manage-policy-file" accept=".json,application/json"></label></p>
  </section>
  <section class="card"><h3>Blocklists</h3>
    ${listRows ? `<table class="mini"><thead><tr><th>Name</th><th>Format</th><th>Entries</th><th>State</th><th>Last</th><th></th></tr></thead><tbody>${listRows}</tbody></table>` : `<p class="muted">No blocklists.</p>`}
    <form id="manage-blocklist" class="policy-line"><input name="name" placeholder="name" required>
      <input name="url" placeholder="https://…/hosts.txt" size="42">
      <select name="format"><option>auto</option><option>hosts</option><option>domains</option><option>ips</option><option>lsrules</option></select>
      <button type="submit">Add blocklist</button></form>
  </section>
  <section class="card"><h3>Profiles and triggers</h3>
    ${profileRows ? `<table class="mini"><thead><tr><th>Name</th><th>Mode</th><th></th><th></th><th></th></tr></thead><tbody>${profileRows}</tbody></table>` : `<p class="muted">No profiles.</p>`}
    <form id="manage-profile" class="policy-line"><input name="name" placeholder="name" required>
      <select name="mode"><option>alert</option><option>silent-allow</option><option>silent-deny</option></select>
      <label><input type="checkbox" name="default"> default for unknown networks</label>
      <button type="submit">Add profile</button></form>
    ${triggerRows ? `<table class="mini"><thead><tr><th>Profile</th><th>Signature</th><th>Action</th><th>Last</th><th></th></tr></thead><tbody>${triggerRows}</tbody></table>` : `<p class="muted">No network triggers.</p>`}
    <form id="manage-trigger" class="policy-line"><select name="profile">${profiles.map((p) => `<option value="${p.id}">${esc(p.name)}</option>`).join("")}</select>
      <input name="signature" placeholder='{"ssid":"home"}' size="40" required>
      <select name="action"><option>activate</option><option>deactivate</option><option>ask</option><option>none</option></select>
      <button type="submit">Add trigger</button></form>
  </section>
  <section class="card"><h3>Open decisions <button type="button" id="manage-scan">Scan this window</button></h3>
    ${decisionRows ? `<table class="mini"><thead><tr><th>When</th><th>Device</th><th>Remote</th><th>Port</th><th>Kind</th><th>Rule</th><th></th></tr></thead><tbody>${decisionRows}</tbody></table>` : `<p class="muted">No open decisions. Scan the window after saving an ask rule.</p>`}
  </section>
  <section class="card"><h3>Rule audit</h3>
    ${auditRows ? `<table class="mini"><thead><tr><th>Rule</th><th>Kind</th><th>Why</th></tr></thead><tbody>${auditRows}</tbody></table>` : `<p class="muted">No findings for the active policy.</p>`}
  </section>`;
}
