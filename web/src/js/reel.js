// A reel is a window's graph with each edge's traffic per step
// (GET /api/v1/reel). Everything here works on one already fetched, so moving
// through time asks the server nothing.

const reelEdgeKey = (e) => `${e.from}\u0000${e.to}\u0000${e.rel}`;

// reelFrame sums each edge's traffic in [t - lookback, t), taking the share of
// a step the interval covers, so motion between steps is smooth. It returns
// Map(edge key -> {up, down}).
export function reelFrame(reel, t, lookback) {
  const out = new Map();
  if (!reel) return out;
  const { from, step } = reel;
  const lo = t - lookback, hi = t;
  const first = Math.floor((lo - from) / step), last = Math.floor((hi - from) / step);
  for (const s of reel.series) {
    const pts = s.points;
    let a = 0, b = pts.length;
    while (a < b) { const m = (a + b) >> 1; if (pts[m][0] < first) a = m + 1; else b = m; }
    let up = 0, down = 0;
    for (let i = a; i < pts.length && pts[i][0] <= last; i++) {
      const start = from + pts[i][0] * step;
      const share = (Math.min(start + step, hi) - Math.max(start, lo)) / step;
      if (share <= 0) continue;
      up += pts[i][1] * share;
      down += pts[i][2] * share;
    }
    if (up > 0 || down > 0) out.set(reelEdgeKey(reel.graph.edges[s.edge]), { up, down });
  }
  return out;
}

// reelDiff compares two frames: an edge busy only in the second was added, only
// in the first removed, and in both by more than a factor of three, changed.
export function reelDiff(a, b) {
  const out = new Map();
  for (const [k, v] of b) {
    const w = a.get(k);
    if (!w) { out.set(k, "added"); continue; }
    const x = v.up + v.down, y = w.up + w.down;
    if (x > y * 3 || y > x * 3) out.set(k, "changed");
  }
  for (const k of a.keys()) if (!b.has(k)) out.set(k, "removed");
  return out;
}
