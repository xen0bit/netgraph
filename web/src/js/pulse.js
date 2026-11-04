// The Pulse: new connections and DHCP as they arrive. Lines are built with
// textContent, because everything in them came off the network.
import { clock } from "./util.js";

const maxLines = 500;

export class Pulse {
  constructor(list, { onOpen, onCount }) {
    this.list = list;
    this.onOpen = onOpen;
    this.onCount = onCount;
    this.paused = false;
    this.held = [];
    this.lines = 0;
    this.query = "";
    this.type = "";
    this.dropped = 0;
    list.addEventListener("click", (e) => {
      const b = e.target.closest("button[data-entity]");
      if (b) this.onOpen(b.dataset.entity);
    });
  }

  matches(ev) {
    if (this.type && ev.type !== this.type) return false;
    if (!this.query) return true;
    return `${ev.label || ""} ${ev.detail || ""}`.toLowerCase().includes(this.query);
  }

  // add takes a batch off the feed. A busy network can send thousands at once;
  // only what fits on the list is drawn, and the rest is counted, not hidden.
  add(evs) {
    if (this.paused) {
      this.held.push(...evs);
      if (this.held.length > maxLines) {
        this.dropped += this.held.length - maxLines;
        this.held.splice(0, this.held.length - maxLines);
      }
      this.onCount(this);
      return;
    }
    const use = evs.filter((e) => this.matches(e));
    if (use.length > maxLines) this.dropped += use.length - maxLines;
    const frag = document.createDocumentFragment();
    for (const e of use.slice(-maxLines).reverse()) frag.append(this.line(e));
    this.list.prepend(frag);
    this.lines += Math.min(use.length, maxLines);
    while (this.lines > maxLines) { this.list.lastElementChild.remove(); this.lines--; }
    this.onCount(this);
  }

  line(e) {
    const li = document.createElement("li");
    const t = document.createElement("time");
    t.textContent = clock(e.ts);
    const kind = document.createElement("span");
    kind.className = "badge";
    kind.textContent = e.type === "flow" ? "connection" : e.type;
    li.append(t, kind);
    if (e.entity) {
      const who = document.createElement("button");
      who.type = "button";
      who.className = "pulse-who";
      who.dataset.entity = e.entity;
      who.textContent = e.label || e.entity;
      li.append(who);
    }
    const d = document.createElement("span");
    d.className = "pulse-detail";
    d.textContent = e.detail;
    li.append(d);
    return li;
  }

  setPaused(on) {
    this.paused = on;
    if (!on) {
      const held = this.held;
      this.held = [];
      if (held.length) this.add(held);
    }
    this.onCount(this);
  }

  clear() {
    this.list.replaceChildren();
    this.lines = 0;
    this.dropped = 0;
    this.held = [];
    this.onCount(this);
  }
}
