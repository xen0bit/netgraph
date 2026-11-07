// What a node is, drawn: 24-unit paths, stroked. Device classes come from the
// server; the names here are our own, never text off the network.
const raw = {
  router: "M3 15h18v5H3zM7 15l3-9M17 15l-3-9M7 17.5h.01M11 17.5h.01",
  ap: "M12 20a1.5 1.5 0 1 0 0-3 1.5 1.5 0 0 0 0 3zM8 14a5.5 5.5 0 0 1 8 0M5 11a10 10 0 0 1 14 0M2 8a14 14 0 0 1 20 0",
  switch: "M3 8h18v8H3zM6 12h.01M9 12h.01M12 12h.01M15 12h.01M18 12h.01",
  device: "M4 5h16v11H4zM2 20h20M9 16v4M15 16v4",
  laptop: "M5 5h14v10H5zM2 19h20l-2-4H4z",
  phone: "M8 2h8a1 1 0 0 1 1 1v18a1 1 0 0 1-1 1H8a1 1 0 0 1-1-1V3a1 1 0 0 1 1-1zM11 19h2",
  tablet: "M6 2h12a1 1 0 0 1 1 1v18a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V3a1 1 0 0 1 1-1zM11 19h2",
  tv: "M3 5h18v12H3zM8 21h8M12 17v4",
  printer: "M7 8V3h10v5M5 8h14a2 2 0 0 1 2 2v6h-4M7 16H3v-6a2 2 0 0 1 2-2M7 13h10v8H7z",
  camera: "M3 8h12v8H3zM15 11l6-3v8l-6-3M7 12h.01",
  speaker: "M7 2h10v20H7zM12 18a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM12 6h.01",
  nas: "M4 3h16v6H4zM4 9h16v6H4zM4 15h16v6H4zM7 6h.01M7 12h.01M7 18h.01",
  server: "M4 4h16v7H4zM4 13h16v7H4zM7 7.5h.01M7 16.5h.01",
  game: "M6 8h12a4 4 0 0 1 4 4v3a3 3 0 0 1-5.4 1.8L15 15H9l-1.6 1.8A3 3 0 0 1 2 15v-3a4 4 0 0 1 4-4zM7 11v3M5.5 12.5h3M16 12h.01M18 14h.01",
  iot: "M12 3a6 6 0 0 1 4 10.5V16H8v-2.5A6 6 0 0 1 12 3zM9 19h6M10 22h4",
  domain: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18",
  ip: "M4 7h16v10H4zM8 12h.01M12 12h.01M16 12h.01",
  asn: "M12 3l8 4.5v9L12 21l-8-4.5v-9z",
  more: "M6 12h.01M12 12h.01M18 12h.01",
  process: "M3 5h18v14H3zM7 10l3 2-3 2M12 15h5",
  note: "M5 3h14v18H5zM8 8h8M8 12h8M8 16h5",
};

const cache = new Map();
export function icon(name) {
  const key = raw[name] ? name : "device";
  if (!cache.has(key)) cache.set(key, new Path2D(raw[key]));
  return cache.get(key);
}

// iconFor picks a node's icon.
export function iconFor(n) {
  const a = n.attrs || {};
  if (a.class && raw[a.class]) return a.class;
  if (/router|gateway/.test(a.role || "")) return "router";
  if (a.role === "access_point") return "ap";
  switch (n.kind) {
    case "device": return "device";
    case "domain": case "site": return "domain";
    case "ip": return "ip";
    case "asn": return "asn";
    case "process": return "process";
    case "other": return "more";
    default: return n.id.startsWith("other:") ? "more" : "note";
  }
}
