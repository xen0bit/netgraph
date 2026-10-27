// Diagram shows an SVG with pan (drag), zoom (wheel, +/-) and fit, and
// reports clicks on d2 shapes as entity IDs.
//
// d2 gives each shape group a class whose first word is the base64 of the
// shape's key, HTML-escaped: our keys are quoted entity IDs, so
// atob("JiMzNDtkZXZpY2U6...") is "&#34;device:...&#34;". Clicking a
// device's grid of destinations reports "dests:<device ID>".
export class Diagram {
  constructor(el, { onSelect } = {}) {
    this.el = el;
    this.onSelect = onSelect;
    this.svg = null;
    this.scale = 1; this.x = 0; this.y = 0;
    let drag = null;
    el.addEventListener("pointerdown", (e) => {
      if (!this.svg || e.button !== 0) return;
      drag = { x: e.clientX, y: e.clientY, ox: this.x, oy: this.y, moved: false };
      try { el.setPointerCapture(e.pointerId); } catch { /* synthetic or already-released pointer */ }
    });
    el.addEventListener("pointermove", (e) => {
      if (!drag) return;
      const dx = e.clientX - drag.x, dy = e.clientY - drag.y;
      if (Math.abs(dx) + Math.abs(dy) > 3) { drag.moved = true; this.autoFit = false; el.classList.add("dragging"); }
      this.x = drag.ox + dx; this.y = drag.oy + dy; this.apply();
    });
    el.addEventListener("pointerup", (e) => {
      const d = drag; drag = null; el.classList.remove("dragging");
      if (d && !d.moved) this.click(e);
    });
    el.addEventListener("wheel", (e) => {
      if (!this.svg) return;
      e.preventDefault();
      const r = el.getBoundingClientRect();
      this.zoomAt(e.clientX - r.left, e.clientY - r.top, Math.exp(-e.deltaY * 0.0015));
    }, { passive: false });
    el.addEventListener("keydown", (e) => {
      const r = el.getBoundingClientRect();
      if (e.key === "+" || e.key === "=") this.zoomAt(r.width / 2, r.height / 2, 1.2);
      else if (e.key === "-") this.zoomAt(r.width / 2, r.height / 2, 1 / 1.2);
      else if (e.key === "0") this.fit();
      else if (e.key === "ArrowLeft") this.pan(40, 0);
      else if (e.key === "ArrowRight") this.pan(-40, 0);
      else if (e.key === "ArrowUp") this.pan(0, 40);
      else if (e.key === "ArrowDown") this.pan(0, -40);
      else return;
      e.preventDefault();
    });
    new ResizeObserver(() => { if (this.svg && this.autoFit) this.fit(); }).observe(el);
  }

  message(html) {
    this.done();
    this.svg = null;
    this.svgText = null;
    this.el.innerHTML = `<div class="placeholder"><div>${html}</div></div>`;
  }

  // loading keeps the current graph visible under a small status pill while
  // the next one is fetched and laid out. It is not a modal: panning and
  // zooming the old graph still work.
  loading(text = "Loading graph…") {
    this.el.setAttribute("aria-busy", "true");
    let el = this.el.querySelector(".diagram-loading");
    if (!el) {
      el = document.createElement("div");
      el.className = "diagram-loading";
      el.setAttribute("role", "status");
      el.innerHTML = `<span class="spinner" aria-hidden="true"></span><span class="loading-text"></span>`;
      this.el.appendChild(el);
    }
    el.querySelector(".loading-text").textContent = text;
  }

  done() {
    this.el.removeAttribute("aria-busy");
    this.el.querySelector(".diagram-loading")?.remove();
  }

  // show draws svgText. With keepView, a view the person has panned or
  // zoomed is kept rather than refitted: a refresh of the same graph must
  // not throw away where they were looking. The same SVG again is a no-op.
  show(svgText, { keepView = false } = {}) {
    this.done();
    if (this.svg && svgText === this.svgText && keepView) return;
    this.svgText = svgText;
    const prev = { scale: this.scale, x: this.x, y: this.y };
    // The SVG comes from our own WASM renderer or server, never from
    // user-supplied markup: entity labels are escaped by d2.
    this.el.innerHTML = svgText;
    this.svg = this.el.querySelector("svg");
    if (!this.svg) return;
    const vb = this.svg.viewBox.baseVal;
    this.w = vb && vb.width ? vb.width : this.svg.getBBox().width;
    this.h = vb && vb.height ? vb.height : this.svg.getBBox().height;
    this.svg.setAttribute("width", this.w);
    this.svg.setAttribute("height", this.h);
    if (keepView && !this.autoFit) { Object.assign(this, prev); this.apply(); } else this.fit();
  }

  pan(dx, dy) {
    this.autoFit = false;
    this.x += dx; this.y += dy;
    this.apply();
  }

  fit() {
    if (!this.svg) return;
    this.autoFit = true;
    const r = this.el.getBoundingClientRect();
    this.scale = Math.min(r.width / this.w, r.height / this.h, 1.5) * 0.95;
    this.x = (r.width - this.w * this.scale) / 2;
    this.y = (r.height - this.h * this.scale) / 2;
    this.apply();
  }

  zoomAt(px, py, k) {
    this.autoFit = false;
    const s = Math.min(Math.max(this.scale * k, 0.05), 8);
    k = s / this.scale;
    this.x = px - (px - this.x) * k;
    this.y = py - (py - this.y) * k;
    this.scale = s;
    this.apply();
  }

  apply() {
    if (this.svg) this.svg.style.transform = `translate(${this.x}px, ${this.y}px) scale(${this.scale})`;
  }

  click(e) {
    let n = e.target;
    while (n && n !== this.el) {
      if (n.tagName === "g" && n.classList.length > 1) {
        const id = decodeShape(n.classList[0]);
        if (id && /^[a-z]+:/.test(id) && !id.includes("->")) { this.onSelect?.(id); return; }
      }
      n = n.parentNode;
    }
  }
}

// decodeShape returns the entity ID a shape's class names. A shape inside a
// container (a device's grid of destinations) has the d2 path
// "container"."shape": its ID is the last key.
function decodeShape(cls) {
  let s;
  try {
    s = atob(cls);
  } catch {
    return null;
  }
  // Keys are d2 strings: an escaped quote inside one is \&#34;.
  const keys = [...s.matchAll(/&#34;((?:\\.|\\&#34;|[^\\])*?)&#34;/g)].map((m) => m[1].replaceAll("\\&#34;", '"').replace(/\\(.)/g, "$1"));
  const id = (keys.length ? keys[keys.length - 1] : s).replaceAll("&#34;", '"').replaceAll("&amp;", "&").replaceAll("&lt;", "<").replaceAll("&gt;", ">");
  return s.includes("-&gt;") || s.includes("->") ? `${id}->` : id;
}
