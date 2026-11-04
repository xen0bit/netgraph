// layout places a graph's nodes so the picture means something: the router in
// the middle, the devices here around it, and what they talk to outside them,
// each near the device that uses it most. It is a pure function of its input.
//
// Positions already known are kept: a node stays where it was across windows
// and refreshes, so what changes on the map is what changed on the network.

const NODE_GAP = 26;

// A small stable hash: a new device's place must not depend on what else
// happens to be in this window.
export function hash(s) {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
  return h >>> 0;
}

const isHub = (n) => /router|gateway/.test(n.attrs?.role || "");

// layout returns Map(id -> {x, y}) for every node. sizes(id) gives {w, h};
// known is Map(id -> {x, y}) of positions to keep.
export function layout(nodes, edges, sizes, known = new Map()) {
  const out = new Map();
  for (const n of nodes) { const p = known.get(n.id); if (p) out.set(n.id, { x: p.x, y: p.y }); }

  const byId = new Map(nodes.map((n) => [n.id, n]));
  const links = new Map(nodes.map((n) => [n.id, []]));
  const weight = (e) => (e.bytes_out || 0) + (e.bytes_in || 0) + (e.count || 0) + 1;
  for (const e of edges) {
    if (!byId.has(e.from) || !byId.has(e.to)) continue;
    links.get(e.from).push({ id: e.to, w: weight(e) });
    links.get(e.to).push({ id: e.from, w: weight(e) });
  }
  const volume = (id) => links.get(id).reduce((a, l) => a + l.w, 0);

  // --- the devices here -----------------------------------------------------
  const locals = nodes.filter((n) => n.local || n.kind === "device");
  let hub = locals.find(isHub);
  if (!hub && locals.length > 1) {
    // The device others here connect to: a resolver and DHCP server is the
    // router in all but name. A busy laptop has links too, but they go out.
    const isLocal = new Set(locals.map((n) => n.id));
    const accepted = new Map();
    for (const e of edges) if (isLocal.has(e.from) && isLocal.has(e.to)) accepted.set(e.to, (accepted.get(e.to) || 0) + 1);
    const score = (n) => (accepted.get(n.id) || 0) * 1000 + links.get(n.id).length;
    hub = [...locals].sort((a, b) => score(b) - score(a) || (a.id < b.id ? -1 : 1))[0];
  }
  const ring = locals.filter((n) => n !== hub);
  // Devices of one subnet sit together, in a stable order.
  const subnet = (n) => (n.attrs?.addresses || n.sub || "").split(",")[0].replace(/\.\d+$/, "");
  ring.sort((a, b) => subnet(a).localeCompare(subnet(b)) || (a.id < b.id ? -1 : 1));
  const R1 = Math.max(240, (ring.length * 170) / (2 * Math.PI));
  if (hub && !out.has(hub.id)) {
    // The hub goes in the middle unless the devices already placed are centred elsewhere.
    const placed = ring.map((n) => out.get(n.id)).filter(Boolean);
    const c = placed.length ? placed.reduce((a, p) => ({ x: a.x + p.x / placed.length, y: a.y + p.y / placed.length }), { x: 0, y: 0 }) : { x: 0, y: 0 };
    out.set(hub.id, c);
  }
  const centre = hub ? out.get(hub.id) : { x: 0, y: 0 };
  const unplaced = ring.filter((n) => !out.has(n.id));
  if (unplaced.length === ring.length) {
    ring.forEach((n, i) => {
      const a = (i / Math.max(ring.length, 1)) * 2 * Math.PI - Math.PI / 2;
      out.set(n.id, { x: centre.x + R1 * Math.cos(a), y: centre.y + R1 * Math.sin(a) });
    });
  } else {
    // A newcomer takes the free place nearest the angle of its own hash.
    for (const n of unplaced) {
      const a = (hash(n.id) / 2 ** 32) * 2 * Math.PI;
      out.set(n.id, { x: centre.x + R1 * Math.cos(a), y: centre.y + R1 * Math.sin(a) });
    }
  }
  if (!hub && locals.length === 1 && !out.has(locals[0].id)) out.set(locals[0].id, { x: 0, y: 0 });

  // --- everything else ------------------------------------------------------
  // Each remote node belongs to the placed node it exchanges most with. One
  // reached by several devices sits between them instead of outside one.
  const outsiders = nodes.filter((n) => !out.has(n.id));
  const parentOf = new Map();
  for (const n of outsiders) {
    const ls = [...links.get(n.id)].sort((a, b) => b.w - a.w || (a.id < b.id ? -1 : 1));
    const placed = ls.filter((l) => locals.some((x) => x.id === l.id));
    parentOf.set(n.id, placed[0]?.id || ls[0]?.id || "");
  }
  const groups = new Map();
  const shared = [];
  for (const n of outsiders) {
    const placedParents = new Set(links.get(n.id).map((l) => l.id).filter((id) => out.has(id)));
    if (placedParents.size >= 2) { shared.push(n); continue; }
    const p = parentOf.get(n.id);
    if (!groups.has(p)) groups.set(p, []);
    groups.get(p).push(n);
  }
  const angleOf = (p) => Math.atan2(p.y - centre.y, p.x - centre.x);
  for (const n of shared) {
    let sx = 0, sy = 0;
    for (const l of links.get(n.id)) {
      const p = out.get(l.id);
      if (p) { sx += p.x; sy += p.y; }
    }
    const count = links.get(n.id).filter((l) => out.has(l.id)).length;
    const mid = { x: sx / count, y: sy / count };
    const a = Math.hypot(mid.x - centre.x, mid.y - centre.y) < 40 ? (hash(n.id) / 2 ** 32) * 2 * Math.PI : angleOf(mid);
    const r = R1 + 200;
    out.set(n.id, { x: centre.x + r * Math.cos(a), y: centre.y + r * Math.sin(a) });
  }
  // Each parent gets a share of the circle by how much it has to place, at its
  // own angle, in rows outward: busiest nearest.
  const entries = [...groups.entries()].filter(([p]) => out.has(p));
  const total = entries.reduce((a, [, g]) => a + g.length + 1, 0) || 1;
  for (const [p, group] of entries) {
    const at = out.get(p);
    const isCentre = p === hub?.id;
    const base = isCentre ? (hash(p) / 2 ** 32) * 2 * Math.PI : angleOf(at);
    const sector = isCentre ? 2 * Math.PI : Math.max(0.5, Math.min(2.4, (2 * Math.PI * (group.length + 1)) / total));
    group.sort((a, b) => volume(b.id) - volume(a.id) || (a.id < b.id ? -1 : 1));
    let r = (isCentre ? R1 + 180 : 210), i = 0;
    while (i < group.length) {
      const arc = Math.max(sector * r, 120);
      const fit = Math.max(1, Math.floor(arc / 165));
      const row = group.slice(i, i + fit);
      row.forEach((n, j) => {
        const a = base + (row.length === 1 ? 0 : (j / (row.length - 1) - 0.5) * sector);
        out.set(n.id, { x: at.x + r * Math.cos(a), y: at.y + r * Math.sin(a) });
      });
      i += fit;
      r += 74;
    }
  }
  // Nothing to attach to: a row underneath.
  let bx = centre.x - R1;
  for (const n of nodes) {
    if (out.has(n.id)) continue;
    out.set(n.id, { x: bx, y: centre.y + R1 + 420 });
    bx += 170;
  }
  separate(nodes, out, sizes, known);
  return out;
}

// separate pushes overlapping nodes apart on a spatial grid. A node whose
// position was already known never moves: only newcomers give way.
function separate(nodes, pos, sizes, known) {
  const free = nodes.filter((n) => !known.has(n.id));
  if (!free.length) return;
  const cell = 220;
  for (let pass = 0; pass < 12; pass++) {
    const grid = new Map();
    const key = (x, y) => `${Math.floor(x / cell)},${Math.floor(y / cell)}`;
    for (const n of nodes) {
      const p = pos.get(n.id), k = key(p.x, p.y);
      if (!grid.has(k)) grid.set(k, []);
      grid.get(k).push(n);
    }
    let moved = false;
    for (const n of free) {
      const p = pos.get(n.id), s = sizes(n.id);
      const cx = Math.floor(p.x / cell), cy = Math.floor(p.y / cell);
      for (let dx = -1; dx <= 1; dx++) {
        for (let dy = -1; dy <= 1; dy++) {
          for (const o of grid.get(`${cx + dx},${cy + dy}`) || []) {
            if (o === n) continue;
            const q = pos.get(o.id), t = sizes(o.id);
            const ox = (s.w + t.w) / 2 + NODE_GAP - Math.abs(p.x - q.x);
            const oy = (s.h + t.h) / 2 + NODE_GAP - Math.abs(p.y - q.y);
            if (ox <= 0 || oy <= 0) continue;
            moved = true;
            // Along the shallower overlap; identical spots split by hash.
            const tie = (hash(n.id) & 1) ? 1 : -1;
            if (oy < ox) p.y += (p.y === q.y ? tie : Math.sign(p.y - q.y)) * (oy + 1);
            else p.x += (p.x === q.x ? tie : Math.sign(p.x - q.x)) * (ox + 1);
          }
        }
      }
    }
    if (!moved) break;
  }
}
