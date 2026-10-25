// The WASM engine runs here, off the page's thread: d2 lays graphs out with
// a JavaScript engine compiled into Go, which takes a moment on big graphs.
//
// Messages in:  {id, method, request}   (request is a JSON string)
// Messages out: {id, result} | {id, error} | {type: "progress", loaded, total} | {type: "ready", version}
importScripts("js/wasm_exec.js");

let ready;

async function load() {
  const go = new Go();
  const resp = await fetch("web.wasm");
  if (!resp.ok) throw new Error(`web.wasm: ${resp.status}`);
  // Stream the download to report progress: the module is several MB.
  const total = Number(resp.headers.get("Content-Length")) || 0;
  const reader = resp.body.getReader();
  const chunks = [];
  let loaded = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    loaded += value.length;
    postMessage({ type: "progress", loaded, total });
  }
  const bytes = new Uint8Array(loaded);
  let off = 0;
  for (const c of chunks) { bytes.set(c, off); off += c.length; }
  const { instance } = await WebAssembly.instantiate(bytes, go.importObject);
  const started = new Promise((resolve) => { self.netgraphReady = resolve; });
  go.run(instance);
  const version = await started;
  postMessage({ type: "ready", version });
}

ready = load().catch((err) => {
  postMessage({ type: "failed", error: String(err && err.message || err) });
  throw err;
});

onmessage = async (ev) => {
  const { id, method, request } = ev.data;
  try {
    await ready;
    const out = await self.netgraphCall(method, request);
    const parsed = JSON.parse(out);
    if (parsed && parsed.error) postMessage({ id, error: parsed.error });
    else postMessage({ id, result: parsed });
  } catch (err) {
    postMessage({ id, error: String(err && err.message || err) });
  }
};
