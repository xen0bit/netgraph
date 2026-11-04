// The filter box's pure parts. The text grammar stays the source of truth;
// chips and suggestions are a view of it, so a typed filter and a clicked one
// are the same thing and a link holds either.

export const filterKeys = [
  ["device:", "a device: name, MAC or glob"],
  ["type:", "printer, phone, tv…"],
  ["owner:", "whose it is"],
  ["group:", "a group you named"],
  ["domain:", "a name: example.com or *.example.com"],
  ["ip:", "an address or CIDR"],
  ["port:", "the server's port"],
  ["proto:", "tcp, udp, icmp"],
  ["app:", "tls, quic, http, dns…"],
  ["dir:", "out, in, local, external"],
  ["asn:", "a network number"],
  ["cc:", "a country code"],
];

const fixed = {
  type: [["router", ""], ["ap", "access point"], ["switch", ""], ["phone", ""], ["tablet", ""], ["laptop", "computer"], ["tv", ""], ["speaker", ""], ["printer", ""], ["camera", ""], ["nas", "storage"], ["server", ""], ["game", "console"], ["iot", "smart home"]],
  dir: [["out", "a device here connected out"], ["in", "opened from outside"], ["local", "both ends here"], ["external", "neither end here"]],
  proto: [["tcp", ""], ["udp", ""], ["icmp", ""], ["icmpv6", ""]],
  app: [["tls", ""], ["quic", ""], ["http", ""], ["dns", ""], ["dhcp", ""], ["mdns", ""], ["ssdp", ""]],
};

export const tokens = (s) => String(s).trim().split(/\s+/).filter(Boolean);

// lastToken splits what is typed into what's settled and the word in progress.
export function lastToken(s) {
  const i = Math.max(s.lastIndexOf(" "), s.lastIndexOf("\t"));
  return { head: s.slice(0, i + 1), word: s.slice(i + 1) };
}

// localSuggestions are the ones that need no server: keys and fixed values.
export function localSuggestions(word) {
  const i = word.indexOf(":");
  if (i < 0) {
    const w = word.toLowerCase();
    return filterKeys.filter(([k]) => k.startsWith(w)).map(([k, hint]) => ({ text: k, hint, partial: true }));
  }
  const key = word.slice(0, i), v = word.slice(i + 1).toLowerCase();
  return (fixed[key] || []).filter(([x]) => x.startsWith(v)).map(([x, hint]) => ({ text: `${key}:${x}`, hint }));
}

// What each key's value is searched for on the server, and how a result fills
// it in. MACs rather than names: a filter's words can't hold spaces.
export const searched = { device: "device", domain: "domain", ip: "ip", asn: "asn" };
