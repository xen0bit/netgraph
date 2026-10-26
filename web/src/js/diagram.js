// Diagram shows an SVG with pan (drag), zoom (wheel, +/-) and fit, and
// reports clicks on d2 shapes as entity IDs.
//
// d2 gives each shape group a class whose first word is the base64 of the
// shape's key, HTML-escaped: our keys are quoted entity IDs, so
// atob("JiMzNDtkZXZpY2U6...") is "&#34;device:...&#34;".
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
      if (Math.abs(dx) + Math.abs(dy) > 3) { drag.moved = true; el.classList.add("dragging"); }
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
      else if (e.key === "ArrowLeft") { this.x += 40; this.apply(); }
      else if (e.key === "ArrowRight") { this.x -= 40; this.apply(); }
      else if (e.key === "ArrowUp") { this.y += 40; this.apply(); }
      else if (e.key === "ArrowDown") { this.y -= 40; this.apply(); }
      else return;
      e.preventDefault();
    });
    new ResizeObserver(() => { if (this.svg && this.autoFit) this.fit(); }).observe(el);
  }

  message(html) {
    this.done();
    this.svg = null;
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

  show(svgText, { keepView = false } = {}) {
    this.done();
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
    if (keepView) { Object.assign(this, prev); this.apply(); } else this.fit();
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

function decodeShape(cls) {
  try {
    return atob(cls).replaceAll("&#34;", "").replaceAll("&amp;", "&").replaceAll("&lt;", "<").replaceAll("&gt;", ">");
  } catch {
    return null;
  }
}
