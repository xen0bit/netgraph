// Privacy mode: every name and address on the page is a stand-in, for screenshots and
// demos. It works where the data comes in, not where it's drawn, so the map, the tables
// and the details all get the same stand-ins, and it can't miss a place something's
// shown. What goes back to the server is translated back, so everything still works.
//
// Best effort, and it says so: it recognises addresses by their shape and names by the
// field they're in, so a name inside free text it hasn't learned yet can get through.

const IPV4 = String.raw`\b\d{1,3}(?:\.\d{1,3}){3}\b`;
const MAC = String.raw`\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b`;
// At least three colons or a "::", so a time of day isn't an address.
const IPV6 = String.raw`(?:\b[0-9a-f]{1,4}:){3,7}[0-9a-f]{1,4}\b|(?:\b[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*)?::(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*\b)?`;
const DOMAIN = String.raw`\b(?:[a-z0-9_-]+\.)+[a-z]{2,}\b`;
// One pass, longest shape first: a stand-in is never read again as something else,
// as a MAC's stand-in would be as an IPv6 address.
const SHAPES = new RegExp(`(${MAC})|(${IPV6})|(${IPV4})|(${DOMAIN})`, "gi");

// Fields whose whole value is a name.
const NAME_FIELDS = new Set(["label", "auto_label", "device_name", "peer_name", "name", "hostnames", "services", "owner", "groups", "as_org", "sni", "http_host", "qname", "ssid", "src_label", "dst_label", "site", "actor", "user", "agent"]);
// Fields that say nothing about anyone, and that code compares against.
const KEEP = new Set(["kind", "rel", "proto", "app", "state", "direction", "severity", "type", "status", "precision", "source", "end_reason", "role", "signal", "says", "confidence", "tool", "event", "via", "tab", "user_type", "type_confidence", "action", "alpn", "says", "qtype", "rcode", "security"]);
// Free text and fingerprints: nothing here is worth the risk.
const BLANK = new Set(["text", "note", "user_agent", "user_agents", "ja4", "fingerprints", "model", "body", "path", "cmdline", "cmdlines", "started_by", "started by", "code_id", "sha256"]);

const isGenerated = (s) => /^\d+ (more|names?|other)/.test(s) || /^(private|other)$/i.test(s);

export class Privacy {
  constructor(storage) {
    this.storage = storage;
    this.on = false;
    this.fake = new Map(); // real -> stand-in
    this.real = new Map(); // stand-in -> real
    this.count = 0;
    this.load();
  }

  load() {
    try {
      this.on = this.storage.get("netgraph.privacy") === "1";
      const saved = JSON.parse(sessionStorage.getItem("netgraph.privacy.names") || "null");
      if (saved) {
        for (const [r, f] of saved) { this.fake.set(r, f); this.real.set(f, r); }
        this.count = saved.length;
      }
    } catch { /* it starts again with new stand-ins */ }
  }

  save() {
    try { sessionStorage.setItem("netgraph.privacy.names", JSON.stringify([...this.fake])); } catch { /* for this page only */ }
  }

  set(on) {
    if (on) this.storage.set("netgraph.privacy", "1");
    else this.storage.remove("netgraph.privacy");
    this.on = on;
    if (!on) { try { sessionStorage.removeItem("netgraph.privacy.names"); } catch { /* fine */ } }
  }

  alias(value, make) {
    const key = value.toLowerCase();
    let f = this.fake.get(key);
    if (!f) {
      this.count++;
      f = make(this.count);
      this.fake.set(key, f);
      this.real.set(f.toLowerCase(), value);
      this.dirty = true;
    }
    return f;
  }

  // scrub replaces whatever has the shape of an address, and every name it has learned.
  scrub(s) {
    let out = s.replace(SHAPES, (m, mac, v6, v4) => {
      if (this.real.has(m.toLowerCase()) || m === "::") return m; // a stand-in already
      if (mac) return this.alias(m, (n) => `02:00:00:00:${hex2(n >> 8)}:${hex2(n)}`);
      if (v6) return this.alias(m, (n) => `2001:db8::${(n & 0xffff).toString(16)}`);
      if (v4) return this.alias(m, (n) => `198.18.${(n >> 8) & 255}.${n & 255}`);
      return this.alias(m, (n) => `site-${n}.example`);
    });
    for (const [name, f] of this.names || []) {
      if (out.includes(name)) out = out.split(name).join(f);
    }
    return out;
  }

  // name is the stand-in for a whole value that's a name.
  name(v) {
    if (!v || isGenerated(v)) return v;
    const shaped = this.scrub(v);
    if (shaped !== v && (this.real.has(shaped.toLowerCase()) || !/[a-z]{3}/i.test(shaped.replace(/site-\d+\.example/g, "")))) return shaped;
    return this.alias(v, (n) => `name-${n}`);
  }

  // walk returns the same shape of data with everything identifying replaced.
  walk(data) {
    if (!this.on) return data;
    // Names first, so free text mentioning one is caught wherever it comes in the data.
    this.learn(data, "");
    const out = this.visit(data, "");
    if (this.dirty) { this.save(); this.dirty = false; }
    return out;
  }

  learn(v, key) {
    if (Array.isArray(v)) { v.forEach((x) => this.learn(x, key)); return; }
    if (v && typeof v === "object") { for (const [k, x] of Object.entries(v)) this.learn(x, k); return; }
    if (typeof v === "string" && NAME_FIELDS.has(key) && v.length >= 3 && !isGenerated(v)) {
      this.name(v);
      this.dirty = true;
    }
    if (this.dirty) {
      // Longest first: "alice-iphone-2" before "alice-iphone".
      this.names = [...this.fake].filter(([r]) => r.length >= 3).map(([r, f]) => [this.original(r), f]).sort((a, b) => b[0].length - a[0].length);
    }
  }

  original(lower) {
    return this.real.get(this.fake.get(lower).toLowerCase()) || lower;
  }

  visit(v, key) {
    if (Array.isArray(v)) return v.map((x) => this.visit(x, key));
    if (v && typeof v === "object") {
      const o = {};
      for (const [k, x] of Object.entries(v)) o[this.scrub(k)] = this.visit(x, k);
      return o;
    }
    if (typeof v !== "string" || !v) return v;
    if (KEEP.has(key)) return v;
    if (BLANK.has(key)) return "(hidden)";
    if (NAME_FIELDS.has(key)) return this.name(v);
    return this.scrub(v);
  }

  // restore turns stand-ins back, for what goes to the server.
  restore(s) {
    if (!this.on || typeof s !== "string") return s;
    return s
      .replace(/\b02:00:00:00:[0-9a-f]{2}:[0-9a-f]{2}\b/gi, (m) => this.real.get(m.toLowerCase()) || m)
      .replace(/\b198\.18\.\d{1,3}\.\d{1,3}\b/g, (m) => this.real.get(m) || m)
      .replace(/\b2001:db8::[0-9a-f]+\b/gi, (m) => this.real.get(m.toLowerCase()) || m)
      .replace(/\bsite-\d+\.example\b/gi, (m) => this.real.get(m.toLowerCase()) || m)
      .replace(/\bname-\d+\b/gi, (m) => this.real.get(m.toLowerCase()) || m);
  }

  // restorePath does that to a request's path, whose pieces are URL-encoded.
  restorePath(path) {
    if (!this.on) return path;
    const [p, q] = path.split("?");
    const seg = p.split("/").map((x) => encodeURIComponent(this.restore(decodeURIComponent(x)))).join("/");
    if (q === undefined) return seg;
    const params = new URLSearchParams(q);
    for (const [k, v] of [...params]) params.set(k, this.restore(v));
    return `${seg}?${params}`;
  }
}

const hex2 = (n) => (n & 255).toString(16).padStart(2, "0");
