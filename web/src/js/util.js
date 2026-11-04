// Small helpers every part of the web UI shares.

// Everything shown here can come off the network — hostnames, user agents,
// UPnP strings — so every value goes through esc() or textContent.
export const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

export const units = { s: 1e3, m: 6e4, h: 36e5, d: 864e5, w: 6048e5 };
export const parseSpan = (s) => { const m = /^(\d+(?:\.\d+)?)([smhdw])$/.exec(s); return m ? Number(m[1]) * units[m[2]] : null; };
export const fmtSpan = (ms) => {
  for (const [u, v] of [["w", units.w], ["d", units.d], ["h", units.h], ["m", units.m], ["s", units.s]]) {
    if (ms >= v && ms % v === 0) return `${ms / v}${u}`;
  }
  return `${Math.round(ms / 1000)}s`;
};
export const bytes = (n) => {
  n = Number(n || 0);
  if (n < 1000) return `${n}B`;
  const u = ["kB", "MB", "GB", "TB", "PB"];
  let i = -1;
  do { n /= 1000; i++; } while (n >= 1000 && i < u.length - 1);
  return `${n >= 100 ? n.toFixed(0) : n.toFixed(1)}${u[i]}`;
};
export const pad2 = (n) => String(n).padStart(2, "0");
export const clock = (ms) => { const d = new Date(ms); return `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`; };
export const stamp = (ms) => { const d = new Date(ms); return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ${clock(ms)}`; };
export const ago = (ms) => {
  if (ms < units.m) return "moments ago";
  for (const [n, v] of [["day", units.d], ["hour", units.h], ["minute", units.m]]) {
    if (ms >= v) { const c = Math.floor(ms / v); return `${c} ${n}${c === 1 ? "" : "s"} ago`; }
  }
  return "moments ago";
};
