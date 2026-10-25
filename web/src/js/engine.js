// Engine is the page's handle on the WASM worker: call(method, request)
// returns a promise of the result.
export class Engine {
  constructor({ onProgress, onReady, onFailed } = {}) {
    this.worker = new Worker("worker.js");
    this.next = 1;
    this.pending = new Map();
    this.ready = false;
    this.failed = null;
    this.worker.onmessage = (ev) => {
      const m = ev.data;
      if (m.type === "progress") { onProgress?.(m.loaded, m.total); return; }
      if (m.type === "ready") { this.ready = true; onReady?.(m.version); return; }
      if (m.type === "failed") {
        this.failed = m.error;
        onFailed?.(m.error);
        for (const p of this.pending.values()) p.reject(new Error(m.error));
        this.pending.clear();
        return;
      }
      const p = this.pending.get(m.id);
      if (!p) return;
      this.pending.delete(m.id);
      if (m.error) p.reject(new Error(m.error)); else p.resolve(m.result);
    };
    this.worker.onerror = (ev) => {
      this.failed = ev.message || "worker failed";
      onFailed?.(this.failed);
    };
  }

  call(method, request = {}) {
    if (this.failed) return Promise.reject(new Error(this.failed));
    const id = this.next++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.worker.postMessage({ id, method, request: JSON.stringify(request) });
    });
  }
}
