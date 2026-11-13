// LivingMap draws a graph on a canvas: nodes keep their places, new ones fade
// in and old ones out, an edge's width is its volume and its particles are its
// direction and rate. Canvas text is not markup, so names off the network
// cannot inject anything here; the DOM parts use textContent.
import { layout } from "./layout.js";
import { icon, iconFor } from "./icons.js";

const FADE_MS = 450;
const MOVE_MS = 500;
const MAX_PARTICLES = 700;
const FONT = '12px system-ui, -apple-system, "Segoe UI", sans-serif';
const FONT_SMALL = '10px system-ui, -apple-system, "Segoe UI", sans-serif';
// LABEL_SCALE is the zoom below which a node's own text is too small to read.
const LABEL_SCALE = 0.28;

const PALETTES = {
  light: {
    added: "#16a34a", removed: "#dc2626", changed: "#d97706",
    bg: "#ffffff", grid: "#eef1f5", text: "#111827", sub: "#6b7280", edge: "#94a3b8", dns: "#16a34a", cname: "#9ca3af",
    up: "#2563eb", down: "#7c3aed", high: "#dc2626", medium: "#ea580c", sel: "#2563eb", halo: "rgba(37,99,235,.14)", lasso: "rgba(37,99,235,.12)",
    kinds: {
      device: ["#dbeafe", "#2563eb"], domain: ["#dcfce7", "#16a34a"], site: ["#dcfce7", "#16a34a"], ip: ["#f3f4f6", "#6b7280"],
      asn: ["#ccfbf1", "#0f766e"], other: ["#ffffff", "#9ca3af"], rest: ["#f9fafb", "#9ca3af"],
    },
  },
  dark: {
    added: "#4ade80", removed: "#f87171", changed: "#fbbf24",
    bg: "#0f1419", grid: "#1a2129", text: "#e5e7eb", sub: "#9ca3af", edge: "#475569", dns: "#22c55e", cname: "#6b7280",
    up: "#60a5fa", down: "#c084fc", high: "#f87171", medium: "#fb923c", sel: "#60a5fa", halo: "rgba(96,165,250,.18)", lasso: "rgba(96,165,250,.16)",
    kinds: {
      device: ["#1e3a5f", "#60a5fa"], domain: ["#14352a", "#22c55e"], site: ["#14352a", "#22c55e"], ip: ["#1f2933", "#9ca3af"],
      asn: ["#123532", "#2dd4bf"], other: ["#111827", "#6b7280"], rest: ["#111827", "#6b7280"],
    },
  },
};

const ease = (t) => 1 - (1 - t) ** 3;
const clamp = (v, a, b) => Math.min(Math.max(v, a), b);
const edgeKey = (e) => `${e.from}\u0000${e.to}\u0000${e.rel}`;
export const humanBytes = (n) => {
  n = Number(n || 0);
  if (n < 1000) return `${n}B`;
  const u = ["kB", "MB", "GB", "TB", "PB"];
  let i = -1;
  do { n /= 1000; i++; } while (n >= 1000 && i < u.length - 1);
  return `${n >= 100 ? n.toFixed(0) : n.toFixed(1)}${u[i]}`;
};

const trunc = (s, n) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

export class LivingMap {
  // handlers: onSelect(id), onEdge(edge), onExpand(id), onMenu(target, x, y),
  // onPin(id, x, y), onUnpin(id), onSelection(ids), onDraw().
  constructor(el, handlers = {}) {
    this.el = el;
    this.h = handlers;
    this.canvas = document.createElement("canvas");
    this.canvas.tabIndex = 0;
    this.canvas.setAttribute("role", "application");
    this.canvas.setAttribute("aria-label", "Network map. Arrow keys move between nodes, Enter opens one, plus and minus zoom, zero fits. The list after this has the same nodes.");
    this.ctx = this.canvas.getContext("2d");
    this.tooltip = document.createElement("div");
    this.tooltip.className = "map-tooltip";
    this.tooltip.hidden = true;
    this.overlay = document.createElement("div");
    this.overlay.className = "placeholder";
    this.overlay.hidden = true;
    this.pill = document.createElement("div");
    this.pill.className = "diagram-loading";
    this.pill.setAttribute("role", "status");
    this.pill.hidden = true;
    const dot = document.createElement("span");
    dot.className = "spinner";
    dot.setAttribute("aria-hidden", "true");
    this.pillText = document.createElement("span");
    this.pill.append(dot, this.pillText);
    this.list = document.createElement("ul");
    this.list.className = "sr-only map-list";
    this.list.setAttribute("aria-label", "Nodes on the map");
    el.append(this.canvas, this.tooltip, this.overlay, this.pill, this.list);

    this.nodes = new Map();  // id -> drawn node
    this.edges = new Map();  // key -> drawn edge
    this.known = this.loadKnown();
    this.pins = new Map();
    this.hidden = new Set();
    this.selected = new Set();
    this.focus = "";
    this.hover = null;
    this.scale = 1; this.x = 0; this.y = 0; this.autoFit = true;
    this.dirty = true;
    this.reduced = matchMedia("(prefers-reduced-motion: reduce)");
    this.theme = "light";
    this.pal = PALETTES.light;
    this.frames = [];
    this.running = false;
    this.spanMS = 3600_000;
    this.measure = document.createElement("canvas").getContext("2d");
    el.__map = this; // for tests and the console
    this.bindInput();
    new ResizeObserver(() => this.resize()).observe(el);
    this.resize();
    document.addEventListener("visibilitychange", () => this.wake());
  }

  // --- what other parts of the page drive -----------------------------------

  setTheme(t) {
    this.theme = t === "dark" ? "dark" : "light";
    this.pal = PALETTES[this.theme];
    this.wake();
  }

  message(html) {
    this.done();
    this.clear();
    // The caller's text and numbers only; see emptyAction in main.js.
    this.overlay.innerHTML = `<div>${html}</div>`;
    this.overlay.hidden = false;
  }

  loading(text = "Loading map…") {
    this.el.setAttribute("aria-busy", "true");
    this.pillText.textContent = text;
    this.pill.hidden = false;
  }

  done() {
    this.el.removeAttribute("aria-busy");
    this.pill.hidden = true;
  }

  clear() {
    for (const k of this.nodes.keys()) this.known.set(k, { x: this.nodes.get(k).tx, y: this.nodes.get(k).ty });
    this.nodes.clear();
    this.edges.clear();
    this.hover = null;
    this.tooltip.hidden = true;
    this.canvas.dataset.nodes = "0";
    this.canvas.dataset.edges = "0";
    this.list.textContent = "";
    this.dirty = true;
    this.wake();
  }

  setPins(pins) {
    this.pins = new Map(pins.map((p) => [p.id, { x: p.x, y: p.y }]));
    for (const [id, p] of this.pins) {
      this.known.set(id, p);
      const n = this.nodes.get(id);
      if (n) { n.pinned = true; this.moveTo(n, p.x, p.y); }
    }
    this.wake();
  }

  // show draws a graph. Nodes already here keep their places and tween to any
  // new size; keepView keeps a view the person has panned or zoomed.
  show(graph, { keepView = false, spanMS = 3600_000 } = {}) {
    this.done();
    this.overlay.hidden = true;
    this.spanMS = Math.max(spanMS, 1000);
    const now = performance.now();
    const nodes = (graph.nodes || []).filter((n) => !this.hidden.has(n.id));
    const ids = new Set(nodes.map((n) => n.id));
    const edges = (graph.edges || []).filter((e) => ids.has(e.from) && ids.has(e.to));
    this.graph = { nodes, edges };

    const sizes = new Map(nodes.map((n) => [n.id, this.sizeOf(n)]));
    const known = new Map();
    for (const n of nodes) {
      const d = this.nodes.get(n.id);
      const p = this.pins.get(n.id) || (d ? { x: d.tx, y: d.ty } : this.known.get(n.id));
      if (p) known.set(n.id, p);
    }
    const pos = layout(nodes, edges, (id) => sizes.get(id), known);

    for (const [id, d] of this.nodes) {
      if (!ids.has(id) && !d.dying) { d.dying = now; this.known.set(id, { x: d.tx, y: d.ty }); }
    }
    for (const n of nodes) {
      const p = pos.get(n.id), s = sizes.get(n.id);
      let d = this.nodes.get(n.id);
      if (!d) {
        d = { id: n.id, x: p.x, y: p.y, tx: p.x, ty: p.y, fx: p.x, fy: p.y, moved: 0, born: now, dying: 0 };
        this.nodes.set(n.id, d);
      }
      d.dying = 0;
      d.data = n;
      d.w = s.w; d.h = s.h; d.shape = s.shape; d.label = s.label; d.sub = s.sub;
      d.icon = iconFor(n);
      d.pinned = this.pins.has(n.id);
      if (p.x !== d.tx || p.y !== d.ty) this.moveTo(d, p.x, p.y);
      this.known.set(n.id, { x: p.x, y: p.y });
    }

    const keys = new Set();
    const between = new Map();
    for (const e of edges) {
      const k = edgeKey(e);
      keys.add(k);
      const pair = e.from < e.to ? `${e.from}\u0000${e.to}` : `${e.to}\u0000${e.from}`;
      const nth = between.get(pair) || 0;
      between.set(pair, nth + 1);
      let d = this.edges.get(k);
      if (!d) {
        d = { key: k, born: now, dying: 0, width: 0, fromWidth: 0, widthAt: now };
        this.edges.set(k, d);
      }
      d.dying = 0;
      d.data = e;
      d.from = e.from; d.to = e.to;
      d.nth = nth;
      const vol = (e.bytes_out || 0) + (e.bytes_in || 0);
      const target = e.rel === "connects" ? clamp(0.8 + Math.log10(vol + 1) * 0.55, 1, 7) : 1;
      if (target !== d.target) { d.fromWidth = d.width; d.widthAt = now; d.target = target; }
      d.dashed = e.rel !== "connects";
      d.up = e.bytes_out || 0;
      d.down = e.bytes_in || 0;
      d.mark = e.attrs?.anomaly || "";
    }
    for (const [k, d] of this.edges) if (!keys.has(k) && !d.dying) d.dying = now;

    this.assignParticles();
    if (this.frame) this.applyFrame(this.frame, this.frameLookback);
    this.renderList();
    this.canvas.dataset.nodes = String(nodes.length);
    this.canvas.dataset.edges = String(edges.length);
    if (!keepView || this.autoFit) this.fit();
    this.saveKnown();
    this.wake();
    this.h.onDraw?.();
  }

  // applyMarks outlines what anomalies are about, on the graph already drawn.
  applyMarks(apply) {
    if (!this.graph) return;
    apply(this.graph);
    for (const d of this.edges.values()) d.mark = d.data?.attrs?.anomaly || "";
    this.dirty = true;
    this.wake();
  }

  // applyFrame shows one moment of a reel: frame is Map(edge key -> {up, down}),
  // bytes in the lookback. What was quiet then stays in its place, ghosted, so
  // the eye sees activity move across a map that holds still.
  applyFrame(frame, lookbackMS = 300_000) {
    this.frame = frame;
    this.frameLookback = lookbackMS;
    const seconds = Math.max(lookbackMS / 1000, 1);
    this.activeNodes = new Set();
    let budget = MAX_PARTICLES;
    for (const d of this.edges.values()) {
      if (d.dying) continue;
      const v = frame?.get(d.key);
      d.frameOn = Boolean(v);
      if (!frame) { continue; }
      if (v) {
        this.activeNodes.add(d.from);
        this.activeNodes.add(d.to);
        const rate = (x) => (x > 0 ? clamp(Math.round(Math.log10(x / seconds + 10)), 1, 6) : 0);
        d.nUp = Math.min(rate(v.up), budget); budget -= d.nUp;
        d.nDown = Math.min(rate(v.down), budget); budget -= d.nDown;
        d.speed = clamp(0.06 + Math.log10((v.up + v.down) / seconds + 1) * 0.035, 0.05, 0.3);
        d.frameWidth = clamp(0.8 + Math.log10(v.up + v.down + 1) * 0.55, 1, 7);
      } else {
        d.nUp = 0; d.nDown = 0;
      }
    }
    if (!frame) this.assignParticles();
    this.canvas.dataset.active = String(this.activeNodes.size);
    this.wake();
  }

  // setDiff colours edges by what changed between two moments:
  // Map(edge key -> "added" | "removed" | "changed"), or null to stop.
  setDiff(diff) {
    this.diff = diff;
    this.diffNodes = null;
    if (diff) {
      this.diffNodes = new Map();
      const rank = { changed: 1, removed: 2, added: 3 };
      for (const d of this.edges.values()) {
        const st = diff.get(d.key);
        if (!st) continue;
        for (const id of [d.from, d.to]) {
          if ((rank[st] || 0) > (rank[this.diffNodes.get(id)] || 0)) this.diffNodes.set(id, st);
        }
      }
    }
    this.wake();
  }

  hide(ids) { for (const id of ids) this.hidden.add(id); }
  showHidden() { this.hidden.clear(); }
  hiddenCount() { return this.hidden.size; }

  // rearrange forgets every place that was not pinned.
  rearrange() {
    this.known = new Map(this.pins);
    const keep = this.nodes;
    const old = new Map();
    for (const [id, d] of keep) old.set(id, d);
    if (!this.graph) return;
    const sizes = new Map(this.graph.nodes.map((n) => [n.id, this.sizeOf(n)]));
    const pos = layout(this.graph.nodes, this.graph.edges, (id) => sizes.get(id), new Map(this.pins));
    for (const [id, p] of pos) {
      const d = keep.get(id);
      if (d) this.moveTo(d, p.x, p.y);
      this.known.set(id, p);
    }
    this.saveKnown();
    this.fit();
    this.wake();
  }

  fit() {
    const live = [...this.nodes.values()].filter((d) => !d.dying);
    this.autoFit = true;
    if (!live.length) { this.scale = 1; this.x = this.W / 2; this.y = this.H / 2; this.wake(); return; }
    let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
    for (const d of live) {
      x0 = Math.min(x0, d.tx - d.w / 2); x1 = Math.max(x1, d.tx + d.w / 2);
      y0 = Math.min(y0, d.ty - d.h / 2); y1 = Math.max(y1, d.ty + d.h / 2);
    }
    const w = x1 - x0 + 80, h = y1 - y0 + 80;
    this.scale = clamp(Math.min(this.W / w, this.H / h), 0.05, 1.4);
    this.x = this.W / 2 - ((x0 + x1) / 2) * this.scale;
    this.y = this.H / 2 - ((y0 + y1) / 2) * this.scale;
    this.publishView();
    this.wake();
  }

  zoomAt(px, py, k) {
    this.autoFit = false;
    const s = clamp(this.scale * k, 0.05, 6);
    k = s / this.scale;
    this.x = px - (px - this.x) * k;
    this.y = py - (py - this.y) * k;
    this.scale = s;
    this.publishView();
    this.wake();
  }

  pan(dx, dy) {
    this.autoFit = false;
    this.x += dx; this.y += dy;
    this.publishView();
    this.wake();
  }

  // Where a node is on the screen, for a person's next step and for tests.
  screenOf(id) {
    const d = this.nodes.get(id);
    if (!d) return null;
    const r = this.canvas.getBoundingClientRect();
    return { x: r.left + d.x * this.scale + this.x, y: r.top + d.y * this.scale + this.y };
  }

  publishView() {
    this.canvas.dataset.view = `${this.x.toFixed(1)},${this.y.toFixed(1)},${this.scale.toFixed(4)}`;
  }

  toPNG() { return this.canvas.toDataURL("image/png"); }

  // --- sizes and places ------------------------------------------------------

  sizeOf(n) {
    const local = n.local || n.kind === "device";
    const label = trunc(n.label || n.id, local ? 26 : 30);
    const sub = trunc(n.sub || "", 34);
    this.measure.font = FONT;
    const lw = this.measure.measureText(label).width;
    this.measure.font = FONT_SMALL;
    const sw = this.measure.measureText(sub).width;
    const w = Math.max(local ? 118 : 96, Math.max(lw, sw) + 44);
    const h = sub ? (local ? 46 : 42) : 32;
    const shape = local ? "rect" : n.kind === "domain" || n.kind === "site" ? "pill" : n.kind === "asn" ? "chamfer" : "rect";
    return { w, h, shape, label, sub };
  }

  moveTo(d, x, y) {
    d.fx = d.x; d.fy = d.y;
    d.tx = x; d.ty = y;
    d.moved = this.reduced.matches ? 0 : performance.now();
    if (!d.moved) { d.x = x; d.y = y; }
  }

  loadKnown() {
    try {
      const raw = JSON.parse(localStorage.getItem("netgraph.map.places") || "[]");
      return new Map(raw.map(([id, x, y]) => [id, { x, y }]));
    } catch { return new Map(); }
  }

  // Places persist between visits in this browser, newest kept; pins persist
  // on the server, for every browser.
  saveKnown() {
    clearTimeout(this.saveTimer);
    this.saveTimer = setTimeout(() => {
      const rows = [...this.known].slice(-3000).map(([id, p]) => [id, Math.round(p.x), Math.round(p.y)]);
      try { localStorage.setItem("netgraph.map.places", JSON.stringify(rows)); } catch { /* private mode */ }
    }, 500);
  }

  assignParticles() {
    if (this.frame) return;
    const live = [...this.edges.values()].filter((d) => !d.dying && !d.dashed);
    const seconds = this.spanMS / 1000;
    let budget = MAX_PARTICLES;
    live.sort((a, b) => (b.up + b.down) - (a.up + a.down));
    for (const d of live) {
      // Dots are a logarithm of the rate, so a trickle still shows and a flood
      // does not fill the screen.
      const count = (v) => {
        const rate = v / seconds;
        return v > 0 ? clamp(Math.round(Math.log10(rate + 10)) , 1, 6) : 0;
      };
      d.nUp = Math.min(count(d.up), budget); budget -= d.nUp;
      d.nDown = Math.min(count(d.down), budget); budget -= d.nDown;
      d.speed = clamp(0.06 + Math.log10((d.up + d.down) / seconds + 1) * 0.035, 0.05, 0.3);
    }
  }

  renderList() {
    const frag = document.createDocumentFragment();
    for (const n of this.graph.nodes) {
      const li = document.createElement("li");
      const b = document.createElement("button");
      b.type = "button";
      b.dataset.id = n.id;
      b.textContent = n.sub ? `${n.label}, ${n.sub}` : n.label;
      b.addEventListener("click", () => this.h.onSelect?.(n.id));
      li.append(b);
      frag.append(li);
    }
    this.list.textContent = "";
    this.list.append(frag);
  }

  // --- input -----------------------------------------------------------------

  toWorld(e) {
    const r = this.canvas.getBoundingClientRect();
    const px = e.clientX - r.left, py = e.clientY - r.top;
    return { px, py, x: (px - this.x) / this.scale, y: (py - this.y) / this.scale };
  }

  nodeAt(x, y) {
    let best = null;
    for (const d of this.nodes.values()) {
      if (d.dying) continue;
      if (Math.abs(x - d.x) <= d.w / 2 + 2 && Math.abs(y - d.y) <= d.h / 2 + 2) best = d;
    }
    return best;
  }

  edgeAt(x, y) {
    const tol = Math.max(6 / this.scale, 3);
    let best = null, bestD = tol;
    for (const d of this.edges.values()) {
      if (d.dying || !d.c) continue;
      const { ax, ay, cx, cy, bx, by } = d.c;
      if (x < Math.min(ax, bx, cx) - tol || x > Math.max(ax, bx, cx) + tol || y < Math.min(ay, by, cy) - tol || y > Math.max(ay, by, cy) + tol) continue;
      for (let i = 0; i <= 16; i++) {
        const t = i / 16, u = 1 - t;
        const qx = u * u * ax + 2 * u * t * cx + t * t * bx, qy = u * u * ay + 2 * u * t * cy + t * t * by;
        const dist = Math.hypot(qx - x, qy - y);
        if (dist < bestD) { bestD = dist; best = d; }
      }
    }
    return best;
  }

  bindInput() {
    const c = this.canvas;
    let drag = null;
    const touches = new Map();
    let pinch = null;
    c.addEventListener("pointerdown", (e) => {
      if (e.button !== 0) return;
      c.focus({ preventScroll: true });
      if (e.pointerType === "touch") {
        touches.set(e.pointerId, { x: e.clientX, y: e.clientY });
        if (touches.size === 2) { drag = null; pinch = null; return; }
      }
      const w = this.toWorld(e);
      const node = this.nodeAt(w.x, w.y);
      if (e.shiftKey && !node) drag = { kind: "lasso", x0: w.x, y0: w.y, x1: w.x, y1: w.y };
      else if (node) drag = { kind: "node", node, sx: e.clientX, sy: e.clientY, ox: node.tx, oy: node.ty, moved: false };
      else drag = { kind: "pan", sx: e.clientX, sy: e.clientY, ox: this.x, oy: this.y, moved: false, world: w };
      try { c.setPointerCapture(e.pointerId); } catch { /* synthetic pointer */ }
    });
    c.addEventListener("pointermove", (e) => {
      if (touches.has(e.pointerId)) {
        touches.set(e.pointerId, { x: e.clientX, y: e.clientY });
        if (touches.size === 2) {
          const [a, b] = [...touches.values()];
          const d = Math.hypot(a.x - b.x, a.y - b.y);
          const r = c.getBoundingClientRect();
          if (pinch) this.zoomAt((a.x + b.x) / 2 - r.left, (a.y + b.y) / 2 - r.top, d / pinch);
          pinch = d;
          return;
        }
      }
      if (!drag) { this.onHover(e); return; }
      const dx = e.clientX - drag.sx, dy = e.clientY - drag.sy;
      if (drag.kind === "lasso") {
        const w = this.toWorld(e);
        drag.x1 = w.x; drag.y1 = w.y;
        this.lasso = drag;
        this.wake();
      } else if (Math.abs(dx) + Math.abs(dy) > 3 || drag.moved) {
        drag.moved = true;
        this.el.classList.add("dragging");
        this.tooltip.hidden = true;
        if (drag.kind === "pan") {
          this.autoFit = false;
          this.x = drag.ox + dx; this.y = drag.oy + dy;
          this.publishView();
        } else {
          const n = drag.node;
          n.tx = n.x = drag.ox + dx / this.scale;
          n.ty = n.y = drag.oy + dy / this.scale;
          n.moved = 0;
        }
        this.wake();
      }
    });
    const end = (e) => {
      touches.delete(e.pointerId);
      if (touches.size < 2) pinch = null;
      const d = drag;
      drag = null;
      this.el.classList.remove("dragging");
      if (!d) return;
      if (d.kind === "lasso") {
        this.lasso = null;
        const [x0, x1] = [Math.min(d.x0, d.x1), Math.max(d.x0, d.x1)];
        const [y0, y1] = [Math.min(d.y0, d.y1), Math.max(d.y0, d.y1)];
        this.selected = new Set([...this.nodes.values()].filter((n) => !n.dying && n.x >= x0 && n.x <= x1 && n.y >= y0 && n.y <= y1).map((n) => n.id));
        this.h.onSelection?.([...this.selected]);
        this.wake();
        return;
      }
      if (d.moved) {
        if (d.kind === "node") {
          const n = d.node;
          n.pinned = true;
          this.pins.set(n.id, { x: n.tx, y: n.ty });
          this.known.set(n.id, { x: n.tx, y: n.ty });
          this.autoFit = false;
          this.saveKnown();
          this.h.onPin?.(n.id, n.tx, n.ty);
        }
        return;
      }
      if (e.type !== "pointerup") return;
      if (d.kind === "node") {
        this.focus = d.node.id;
        if (this.selected.size) { this.selected.clear(); this.h.onSelection?.([]); }
        this.h.onSelect?.(d.node.id);
        this.wake();
      } else {
        const edge = this.edgeAt(d.world.x, d.world.y);
        if (edge) this.h.onEdge?.(edge.data);
        else if (this.selected.size) { this.selected.clear(); this.h.onSelection?.([]); this.wake(); }
      }
    };
    c.addEventListener("pointerup", end);
    c.addEventListener("pointercancel", end);
    c.addEventListener("pointerleave", () => { if (this.hover) { this.hover = null; this.tooltip.hidden = true; this.wake(); } });
    c.addEventListener("wheel", (e) => {
      e.preventDefault();
      const w = this.toWorld(e);
      this.zoomAt(w.px, w.py, Math.exp(-e.deltaY * 0.0015));
    }, { passive: false });
    c.addEventListener("dblclick", (e) => {
      const w = this.toWorld(e);
      const n = this.nodeAt(w.x, w.y);
      if (n) this.h.onExpand?.(n.id);
    });
    c.addEventListener("contextmenu", (e) => {
      e.preventDefault();
      const w = this.toWorld(e);
      const n = this.nodeAt(w.x, w.y);
      const edge = n ? null : this.edgeAt(w.x, w.y);
      this.h.onMenu?.({ node: n?.data || null, edge: edge?.data || null, pinned: n?.pinned || false }, e.clientX, e.clientY);
    });
    c.addEventListener("keydown", (e) => {
      const k = e.key;
      const r = c.getBoundingClientRect();
      if (k === "+" || k === "=") this.zoomAt(r.width / 2, r.height / 2, 1.2);
      else if (k === "-") this.zoomAt(r.width / 2, r.height / 2, 1 / 1.2);
      else if (k === "0") this.fit();
      else if (k === "Enter" && this.focus) this.h.onSelect?.(this.focus);
      else if (k.startsWith("Arrow")) {
        if (e.shiftKey || !this.nodes.size) {
          const step = 40;
          this.pan(k === "ArrowLeft" ? step : k === "ArrowRight" ? -step : 0, k === "ArrowUp" ? step : k === "ArrowDown" ? -step : 0);
        } else this.moveFocus(k);
      } else return;
      e.preventDefault();
    });
  }

  // moveFocus goes to the nearest node in the direction of the arrow, and
  // brings it on screen.
  moveFocus(k) {
    const cur = this.nodes.get(this.focus);
    const live = [...this.nodes.values()].filter((d) => !d.dying);
    if (!live.length) return;
    let next = null;
    if (!cur) next = live.find((d) => d.data?.local || d.data?.kind === "device") || live[0];
    else {
      const dir = { ArrowLeft: [-1, 0], ArrowRight: [1, 0], ArrowUp: [0, -1], ArrowDown: [0, 1] }[k];
      let best = Infinity;
      for (const d of live) {
        if (d === cur) continue;
        const dx = d.x - cur.x, dy = d.y - cur.y;
        const along = dx * dir[0] + dy * dir[1];
        if (along <= 0) continue;
        const score = along + Math.abs(dx * dir[1]) * 2 + Math.abs(dy * dir[0]) * 2;
        if (score < best) { best = score; next = d; }
      }
    }
    if (!next) return;
    this.focus = next.id;
    const sx = next.x * this.scale + this.x, sy = next.y * this.scale + this.y;
    if (sx < 60 || sx > this.W - 60 || sy < 40 || sy > this.H - 40) this.pan(this.W / 2 - sx, this.H / 2 - sy);
    this.showTip(next.data, sx, sy);
    this.wake();
  }

  onHover(e) {
    const w = this.toWorld(e);
    const n = this.nodeAt(w.x, w.y);
    const edge = n ? null : this.edgeAt(w.x, w.y);
    const key = n ? `n${n.id}` : edge ? `e${edge.key}` : "";
    if (key !== this.hoverKey) {
      this.hoverKey = key;
      this.hover = n ? { node: n } : edge ? { edge } : null;
      this.neighbours = null;
      if (n) {
        this.neighbours = new Set([n.id]);
        for (const d of this.edges.values()) {
          if (d.dying) continue;
          if (d.from === n.id) this.neighbours.add(d.to);
          if (d.to === n.id) this.neighbours.add(d.from);
        }
      }
      this.canvas.style.cursor = n ? "pointer" : edge ? "pointer" : "";
      this.wake();
    }
    if (n) this.showTip(n.data, w.px, w.py);
    else if (edge) this.showEdgeTip(edge.data, w.px, w.py);
    else this.tooltip.hidden = true;
  }

  placeTip(px, py) {
    const t = this.tooltip;
    t.hidden = false;
    const tw = t.offsetWidth, th = t.offsetHeight;
    t.style.left = `${clamp(px + 14, 4, Math.max(4, this.W - tw - 4))}px`;
    t.style.top = `${clamp(py + 14, 4, Math.max(4, this.H - th - 4))}px`;
  }

  tipLines(lines) {
    this.tooltip.textContent = "";
    lines.forEach(([cls, text]) => {
      if (!text) return;
      const div = document.createElement("div");
      if (cls) div.className = cls;
      div.textContent = text;
      this.tooltip.append(div);
    });
  }

  showTip(n, px, py) {
    const a = n.attrs || {};
    this.tipLines([
      ["tip-title", n.label],
      ["tip-sub", n.sub],
      ["", n.bytes_out || n.bytes_in ? `sent ${humanBytes(n.bytes_out)} · received ${humanBytes(n.bytes_in)}` : ""],
      ["tip-sub", a.serves ? `serves ${a.serves}` : ""],
      ["tip-alert", a.anomalies],
    ]);
    this.placeTip(px, py);
  }

  showEdgeTip(e, px, py) {
    const lines = [["tip-title", edgeTitle(e)]];
    if (e.ports?.length) lines.push(["", e.ports.join(", ")]);
    if (e.bytes_out || e.bytes_in) lines.push(["", `up ${humanBytes(e.bytes_out)} · down ${humanBytes(e.bytes_in)}`]);
    if (e.count) lines.push(["tip-sub", `${e.count} ${e.rel === "connects" ? "connections" : "times"}${e.peak ? `, peak ${e.peak} open` : ""}`]);
    if (e.opened || e.closed || e.carried) lines.push(["tip-sub", [e.carried && `${e.carried} carried`, e.opened && `${e.opened} opened`, e.closed && `${e.closed} closed`].filter(Boolean).join(" · ")]);
    if (e.attrs?.anomalies) lines.push(["tip-alert", e.attrs.anomalies]);
    lines.push(["tip-sub", "Click for its connections"]);
    this.tipLines(lines);
    this.placeTip(px, py);
  }

  // --- drawing ---------------------------------------------------------------

  resize() {
    const r = this.el.getBoundingClientRect();
    this.W = Math.max(r.width, 1); this.H = Math.max(r.height, 1);
    this.dpr = window.devicePixelRatio || 1;
    this.canvas.width = Math.round(this.W * this.dpr);
    this.canvas.height = Math.round(this.H * this.dpr);
    if (this.autoFit && this.nodes.size) this.fit();
    this.wake();
  }

  wake() {
    this.dirty = true;
    if (!this.running) {
      this.running = true;
      requestAnimationFrame((t) => this.tick(t));
    }
  }

  tick(t) {
    const started = performance.now();
    const animating = this.step(t);
    this.draw(t);
    this.frames.push(performance.now() - started);
    if (this.frames.length > 240) this.frames.shift();
    this.canvas.dataset.frameMs = (this.frames.reduce((a, b) => a + b, 0) / this.frames.length).toFixed(2);
    const particles = !this.reduced.matches && !document.hidden && this.el.offsetParent !== null && [...this.edges.values()].some((d) => d.nUp || d.nDown);
    if (animating || particles) requestAnimationFrame((n) => this.tick(n));
    else this.running = false;
  }

  // step advances the tweens, and reports whether any is unfinished.
  step(t) {
    let busy = false;
    const now = performance.now();
    const still = this.reduced.matches;
    for (const [id, d] of this.nodes) {
      if (d.dying && (still || now - d.dying >= FADE_MS)) { this.nodes.delete(id); continue; }
      if (d.moved) {
        const f = (now - d.moved) / MOVE_MS;
        if (f >= 1) { d.x = d.tx; d.y = d.ty; d.moved = 0; }
        else { d.x = d.fx + (d.tx - d.fx) * ease(f); d.y = d.fy + (d.ty - d.fy) * ease(f); busy = true; }
      }
      d.alpha = still ? 1 : d.dying ? 1 - (now - d.dying) / FADE_MS : Math.min(1, (now - d.born) / FADE_MS);
      if (d.alpha < 1) busy = true;
    }
    for (const [k, d] of this.edges) {
      if (d.dying && (still || now - d.dying >= FADE_MS)) { this.edges.delete(k); continue; }
      const f = still ? 1 : Math.min(1, (now - d.widthAt) / MOVE_MS);
      d.width = d.fromWidth + ((d.target || 1) - d.fromWidth) * ease(f);
      if (f < 1) busy = true;
      d.alpha = still ? 1 : d.dying ? 1 - (now - d.dying) / FADE_MS : Math.min(1, (now - d.born) / FADE_MS);
      if (d.alpha < 1) busy = true;
    }
    return busy;
  }

  draw(t) {
    const g = this.ctx, p = this.pal, s = this.scale;
    g.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
    g.fillStyle = p.bg;
    g.fillRect(0, 0, this.W, this.H);
    g.setTransform(this.dpr * s, 0, 0, this.dpr * s, this.dpr * this.x, this.dpr * this.y);
    const view = {
      x0: -this.x / s - 200, y0: -this.y / s - 200,
      x1: (this.W - this.x) / s + 200, y1: (this.H - this.y) / s + 200,
    };
    this.drawEdges(g, view, t);
    this.drawNodes(g, view);
    if (s <= LABEL_SCALE) this.drawFarLabels(g);
    if (this.lasso) {
      const l = this.lasso;
      g.fillStyle = p.lasso;
      g.strokeStyle = p.sel;
      g.lineWidth = 1 / s;
      g.fillRect(l.x0, l.y0, l.x1 - l.x0, l.y1 - l.y0);
      g.strokeRect(l.x0, l.y0, l.x1 - l.x0, l.y1 - l.y0);
    }
  }

  dimmed(id) {
    return this.neighbours && !this.neighbours.has(id);
  }

  geometry(d) {
    const a = this.nodes.get(d.from), b = this.nodes.get(d.to);
    if (!a || !b) { d.c = null; return false; }
    const dx = b.x - a.x, dy = b.y - a.y;
    const len = Math.hypot(dx, dy) || 1;
    const sign = d.from < d.to ? 1 : -1;
    const bend = (0.06 * len + d.nth * 26) * (d.nth % 2 ? -1 : 1) * sign;
    const cx = (a.x + b.x) / 2 - (dy / len) * bend, cy = (a.y + b.y) / 2 + (dx / len) * bend;
    const [ax, ay] = boundary(a, cx, cy);
    const [bx, by] = boundary(b, cx, cy);
    d.c = { ax, ay, cx, cy, bx, by };
    return true;
  }

  drawEdges(g, view, t) {
    const p = this.pal, s = this.scale;
    const dots = [];
    const hoverEdge = this.hover?.edge;
    for (const d of this.edges.values()) {
      if (!this.geometry(d)) continue;
      const c = d.c;
      if (Math.max(c.ax, c.bx, c.cx) < view.x0 || Math.min(c.ax, c.bx, c.cx) > view.x1 || Math.max(c.ay, c.by, c.cy) < view.y0 || Math.min(c.ay, c.by, c.cy) > view.y1) continue;
      const dim = this.neighbours && (this.dimmed(d.from) || this.dimmed(d.to));
      const hot = d === hoverEdge || (this.hover?.node && !dim);
      const quiet = this.frame && !d.frameOn;
      const st = this.diff?.get(d.key);
      g.globalAlpha = (d.alpha ?? 1) * (dim ? 0.12 : hot ? 1 : st ? 1 : quiet ? 0.1 : 0.62);
      const color = st === "added" ? p.added : st === "removed" ? p.removed : st === "changed" ? p.changed
        : d.mark === "high" ? p.high : d.mark === "medium" ? p.medium : d.data?.rel === "queried" ? p.dns : d.dashed ? p.cname : p.edge;
      g.strokeStyle = hot && !d.mark && !st ? p.sel : color;
      const base = this.frame && d.frameOn ? d.frameWidth : quiet ? 1 : d.width || 1;
      g.lineWidth = Math.max(base + (d === hoverEdge ? 1.5 : 0) + (st ? 1 : 0), 0.7 / s);
      g.setLineDash(d.dashed ? [5, 5] : []);
      g.beginPath();
      g.moveTo(c.ax, c.ay);
      g.quadraticCurveTo(c.cx, c.cy, c.bx, c.by);
      g.stroke();
      g.setLineDash([]);
      if (s > 0.25) arrow(g, c, Math.max(6, (d.width || 1) * 2.2), g.strokeStyle);
      if (!dim && !quiet && !this.reduced.matches && s > 0.15 && !d.dying) dots.push(d);
      // A label only when there is room to read it.
      if ((s > 1.15 || d === hoverEdge) && d.data && !d.dashed && d.data.ports?.length) {
        const mx = 0.25 * c.ax + 0.5 * c.cx + 0.25 * c.bx, my = 0.25 * c.ay + 0.5 * c.cy + 0.25 * c.by;
        const text = `${d.data.ports.slice(0, 2).join(", ")}  ↑${humanBytes(d.data.bytes_out)} ↓${humanBytes(d.data.bytes_in)}`;
        g.globalAlpha = dim ? 0.2 : 1;
        g.font = FONT_SMALL;
        const tw = g.measureText(text).width;
        g.fillStyle = p.bg;
        g.fillRect(mx - tw / 2 - 3, my - 7, tw + 6, 14);
        g.fillStyle = p.sub;
        g.textAlign = "center"; g.textBaseline = "middle";
        g.fillText(text, mx, my);
      }
    }
    // Particles: up from client to server, down back. Batched by colour.
    const now = t / 1000;
    const r = clamp(2 / s, 1.2, 4);
    for (const [color, field, reverse] of [[p.up, "nUp", false], [p.down, "nDown", true]]) {
      g.fillStyle = color;
      g.globalAlpha = 0.9;
      g.beginPath();
      for (const d of dots) {
        const n = d[field];
        if (!n) continue;
        const c = d.c;
        for (let i = 0; i < n; i++) {
          let f = (now * d.speed + i / n + (reverse ? 0.5 : 0)) % 1;
          if (reverse) f = 1 - f;
          const u = 1 - f;
          const x = u * u * c.ax + 2 * u * f * c.cx + f * f * c.bx, y = u * u * c.ay + 2 * u * f * c.cy + f * f * c.by;
          g.moveTo(x + r, y);
          g.arc(x, y, r, 0, 6.2832);
        }
      }
      g.fill();
    }
    g.globalAlpha = 1;
  }

  // drawFarLabels names nodes when the map is zoomed too far out for their own
  // text: at a fixed, readable size under each node, the important ones first
  // (anomalies, then devices and local nodes, then the biggest), and never on
  // top of another label. A label that won't fit is left out, not squeezed in.
  drawFarLabels(g) {
    const p = this.pal, s = this.scale;
    g.save();
    g.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
    g.font = FONT_SMALL;
    g.textAlign = "center";
    g.textBaseline = "top";
    g.lineJoin = "round";
    const rank = (d) => {
      const n = d.data, a = n.attrs || {};
      return (a.anomaly ? 0 : n.kind === "device" || n.local ? 1 : 2) * 1e6 - d.w * d.h;
    };
    const placed = [];
    const nodes = [...this.nodes.values()].filter((d) => !d.dying && !this.dimmed(d.id)).sort((a, b) => rank(a) - rank(b));
    for (const d of nodes) {
      const text = d.label;
      if (!text) continue;
      const w = this.measure.measureText(text).width * (10 / 12) + 6;
      const cx = d.x * s + this.x, top = (d.y + d.h / 2) * s + this.y + 2;
      const r = { x0: cx - w / 2, x1: cx + w / 2, y0: top, y1: top + 13 };
      if (r.x1 < 0 || r.x0 > this.W || r.y1 < 0 || r.y0 > this.H) continue;
      if (placed.some((q) => r.x0 < q.x1 && q.x0 < r.x1 && r.y0 < q.y1 && q.y0 < r.y1)) continue;
      placed.push(r);
      g.globalAlpha = d.alpha ?? 1;
      g.strokeStyle = p.bg;
      g.lineWidth = 3;
      g.strokeText(text, cx, top);
      g.fillStyle = p.text;
      g.fillText(text, cx, top);
    }
    g.restore();
  }

  drawNodes(g, view) {
    const p = this.pal, s = this.scale;
    const labels = s > LABEL_SCALE;
    const subs = s > 0.6;
    for (const d of this.nodes.values()) {
      if (d.x + d.w < view.x0 || d.x - d.w > view.x1 || d.y + d.h < view.y0 || d.y - d.h > view.y1) continue;
      const n = d.data;
      const a = n.attrs || {};
      const rest = d.id.startsWith("other:");
      const [fill, stroke] = rest ? p.kinds.rest : p.kinds[n.kind] || p.kinds.ip;
      const dim = this.dimmed(d.id);
      const quiet = this.frame && !this.activeNodes?.has(d.id) && !this.diffNodes?.has(d.id);
      g.globalAlpha = (d.alpha ?? 1) * (dim ? 0.2 : quiet ? 0.3 : 1);
      const sel = this.selected.has(d.id), foc = this.focus === d.id, hov = this.hover?.node === d;
      if (sel || foc || hov) {
        g.fillStyle = p.halo;
        shape(g, d, 6);
        g.fill();
      }
      g.fillStyle = fill;
      const changed = this.diffNodes?.get(d.id);
      g.strokeStyle = changed ? p[changed] : a.anomaly === "high" ? p.high : a.anomaly === "medium" ? p.medium : foc || sel ? p.sel : stroke;
      g.lineWidth = changed ? 2.5 : a.anomaly ? 2.5 : foc || sel ? 2 : 1.2;
      g.setLineDash(rest ? [4, 4] : []);
      shape(g, d, 0);
      g.fill();
      g.stroke();
      g.setLineDash([]);
      if (labels || n.local || n.kind === "device" || a.anomaly) {
        // The icon, then the text: 24-unit icon paths drawn at 16.
        const lx = d.x - d.w / 2 + 8;
        g.save();
        g.translate(lx, d.y - 8);
        g.scale(16 / 24, 16 / 24);
        g.strokeStyle = stroke;
        g.lineWidth = 1.8;
        g.lineCap = "round";
        g.lineJoin = "round";
        g.stroke(icon(d.icon));
        g.restore();
        g.fillStyle = p.text;
        g.textAlign = "left";
        g.textBaseline = "middle";
        g.font = FONT;
        const tx = lx + 22;
        // Zoomed out, text this size is a smudge: drawFarLabels writes it at
        // a readable size instead.
        if (!labels) {
          // the icon alone
        } else if (d.sub && subs) {
          g.fillText(d.label, tx, d.y - 7);
          g.font = FONT_SMALL;
          g.fillStyle = p.sub;
          g.fillText(d.sub, tx, d.y + 8);
        } else g.fillText(d.label, tx, d.y);
      }
      if (d.pinned && labels) {
        g.fillStyle = p.sub;
        g.beginPath();
        g.arc(d.x + d.w / 2 - 6, d.y - d.h / 2 + 6, 2.5, 0, 6.2832);
        g.fill();
      }
    }
    g.globalAlpha = 1;
  }
}

function edgeTitle(e) {
  const names = { connects: "Connections", queried: "Lookups", cname: "Alias", resolves_to: "Resolves to" };
  return names[e.rel] || e.rel.replaceAll("_", " ");
}

function shape(g, d, grow) {
  const x = d.x - d.w / 2 - grow, y = d.y - d.h / 2 - grow, w = d.w + 2 * grow, h = d.h + 2 * grow;
  const r = d.shape === "pill" ? h / 2 : d.shape === "chamfer" ? 2 : 7;
  g.beginPath();
  g.roundRect(x, y, w, h, r);
}

// boundary is where the line from a node's centre towards (x, y) leaves it.
function boundary(n, x, y) {
  const dx = x - n.x, dy = y - n.y;
  if (!dx && !dy) return [n.x, n.y];
  const hw = n.w / 2 + 2, hh = n.h / 2 + 2;
  const t = Math.min(dx ? hw / Math.abs(dx) : Infinity, dy ? hh / Math.abs(dy) : Infinity);
  return [n.x + dx * t, n.y + dy * t];
}

function arrow(g, c, size, color) {
  const dx = c.bx - c.cx, dy = c.by - c.cy;
  const len = Math.hypot(dx, dy) || 1;
  const ux = dx / len, uy = dy / len;
  g.fillStyle = color;
  g.beginPath();
  g.moveTo(c.bx, c.by);
  g.lineTo(c.bx - ux * size - uy * size * 0.5, c.by - uy * size + ux * size * 0.5);
  g.lineTo(c.bx - ux * size + uy * size * 0.5, c.by - uy * size - ux * size * 0.5);
  g.closePath();
  g.fill();
}
