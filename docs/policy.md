# Policies, blocklists, profiles and decisions

netgraph simulates and stores policy; it never touches a firewall. A policy
can be exported to nftables, OpenWrt or OPNsense, or enforced by an optional
host agent, but the server itself remains read-only with respect to traffic.

## Versions

- **Version 1** is the original first-match policy: `from`/`to` selectors,
  ports, action. Existing files and exports keep working.
- **Version 2** adds durable policy objects, directions, priority, remote
  types, `ask`, profiles and a documented precedence order.

A version 2 policy:

```json
{
  "version": 2,
  "name": "home",
  "mode": "precedence",
  "zones": [{"name": "iot", "devices": ["role:camera"]}],
  "defaults": {"egress": "deny", "ingress": "deny", "intra_zone": "allow", "dns": "allow"},
  "rules": [
    {
      "name": "camera updates",
      "action": "allow",
      "direction": "out",
      "priority": "regular",
      "local": {"type": "zone", "values": ["iot"]},
      "remote": {"type": "domain", "values": ["*.vendor.example"]},
      "ports": ["443/tcp"],
      "protocol": "tcp"
    }
  ]
}
```

Useful selectors:

| Local | Remote |
|---|---|
| `any`, `zone`, `device`, `label`, `role`, `app`, `process`, `owner` | `any`, `ip`, `host`, `domain`, `dns`, `broadcast`, `multicast`, `bonjour`, `local` |

`ip` accepts addresses and prefixes. `domain` and `dns` match a name and its
subdomains. `ports` accepts `443`, `8000-9000`, or either with `/tcp` or `/udp`.

## Precedence

The first comparison that differs decides:

1. priority: `extra-high` > `high` > `regular`
2. remote type: `ip` > `host` > `domain` > `dns` > `broadcast` >
   `multicast` > `bonjour` > `local` > `any`
3. fewer values, then longer prefix / longer domain suffix / exact host
4. narrower port range, then lower start port
5. specific protocol over `any`
6. specific process, then via, then owner
7. specific direction over `both`
8. `deny` > `allow` > `ask`
9. earlier rule wins the remaining tie

`ask` is not a denial. A passive server records it as a **would-ask** decision;
only an optional host agent can actually stall a connection.

## Blocklists

Blocklists accept:

- hosts files (`0.0.0.0 ads.example`, `127.0.0.1 tracker.example`)
- plain domain lists
- address/CIDR/range lists
- Little Snitch-style `.lsrules` JSON (`rules`, `denied-remote-domains`,
  `denied-remote-hosts`, `denied-remote-addresses`)

Updates use HTTPS with ETag / `If-Modified-Since`, bounded size and time, and
refuse private/loopback targets by default. The fetched payload is parsed and
discarded; only entries are stored. A disabled entry never matches.

## Profiles and network triggers

A profile groups rules for a network context. A trigger matches the network
signature netgraph can see (SSID, BSSID, router MAC, sensor interface) and can
activate a profile, deactivate the current one, ask, or do nothing. Missing
signature fields are omitted, and `*`/`?` globs are accepted.

`silent-allow` and `silent-deny` still record unconfirmed decisions; they are
not enforcement claims.

## Decisions

`POST /api/v1/decisions/scan` evaluates the active policy over a window and
records one open decision per distinct connection that matched an `ask` rule
(or a silent mode). Answer it with allow, deny, rule or reset. Creating a rule
is recorded as `rule-created`; netgraph does not silently install it.

## CLI

```sh
netgraph policy list
netgraph policy show -id pol_...
netgraph policy create -file policy.json
netgraph policy activate -id pol_...
netgraph policy explain -policy policy.json -conn '{"direction":"out","name":"api.example.com","port":"443","proto":"tcp"}'
netgraph policy audit -id pol_...
netgraph blocklist list
netgraph blocklist add -name ads -url https://example/hosts.txt
netgraph blocklist import -id 1 -file hosts.txt
netgraph blocklist update -id 1
netgraph profile list
netgraph profile trigger-add -profile 1 -signature '{"ssid":"home"}'
netgraph decisions scan -from -1h
netgraph decisions allow -id 3
netgraph purpose import -file manifest.json
netgraph policy backup -out policy.json
netgraph policy restore -file policy.json
```

## Backup bundles

A bundle contains policies, profiles, triggers, blocklists and purpose
metadata. It never contains traffic history, decisions, tokens or keys.
`netgraph policy backup -password ...` encrypts it with AES-256-GCM and
PBKDF2; `-sign-key` signs it with Ed25519. `netgraph policy restore` and
`verify` fail closed on a wrong password, wrong key or tampered payload.
