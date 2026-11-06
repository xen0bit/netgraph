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

- hosts files (`0.0.0.0 ads.example`): each name blocks that host exactly.
  The address in front is where the file sends the name, so it is not blocked,
  and the usual `localhost`/`broadcasthost` lines are skipped.
- plain domain lists: each name blocks itself and its subdomains
- address/CIDR/range lists
- Little Snitch `.lsrules` JSON: `denied-remote-domains`, `denied-remote-hosts`,
  `denied-remote-addresses`, and `deny` rules' `remote-domains`, `remote-hosts`
  and `remote-addresses`. Allow rules and keyword remotes (`any`, `local-net`)
  are not blocks and are skipped.

In what-if and decisions, a blocklist denies connections a device here makes
(never inbound ones), unless a `high` or `extra-high` **allow** rule matches:
that is how to make an exception to a list. The audit flags allow rules that
cover a blocklisted name.

Updates use HTTPS with ETag / `If-Modified-Since`, bounded size and time. The
server refuses to connect to private, loopback, link-local and CGNAT addresses,
checked on every connection it makes (so a name that resolves to one, or a
redirect to one, is refused too). A feed on your own network can be fetched
only with direct database access: `netgraph blocklist update -db ... -allow-private
-allow-http`. The fetched payload is parsed and discarded; only entries are
stored. A disabled entry never matches, and a list's edits (disabled entries)
survive updates.

## Profiles and network triggers

A profile groups rules for a network context. The network is the newest
sensor's: its first interface and that interface's MAC (`router`), and, when
the sensor is itself the access point, the SSID it broadcasts. Beacons from
other access points are only heard and never change it. `GET /api/v1/network`
(and `netgraph profile current`) shows the signature, for example
`{"ssid":"home-net","bssid":"02:…","router":"02:…","iface":"br-lan"}`.

A trigger is a glob over that signature (`*"ssid":"home-net"*`), matched
without regard to case. Triggers are tried in order when the signature
changes; the first match can activate its profile (optionally setting its
mode), deactivate the current one, or do nothing (`none`, `ask`: an `ask`
trigger only records that it matched). A profile chosen by hand stays until
the network changes.

`silent-allow` and `silent-deny` still record unconfirmed decisions; they are
not enforcement claims.

## Decisions

`POST /api/v1/decisions/scan` evaluates the active policy over a window and
records one decision per distinct connection that matched an `ask` rule (or no
rule, under a silent mode). A connection gets one decision, however often it
is scanned. Answer it:

- `allow` or `deny`: recorded as allowed or denied once; nothing else changes.
- `rule` with `{"action": "allow"|"deny"}`: adds a rule for this device and
  this exact destination and port to the active version 2 policy, and records
  `rule-created` with the new rule's ID.
- `reset`: back to open.

Who answered is the caller's identity, not something the request claims.
Decisions follow raw retention, and `db forget` and `db purge` remove them.

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
netgraph profile trigger-add -profile 1 -signature '*"ssid":"home"*'
netgraph decisions scan -from -1h
netgraph decisions allow -id 3
netgraph decisions rule -id 4 -action deny
netgraph purpose import -file manifest.json
netgraph policy backup -out policy.json
netgraph policy restore -file policy.json
```

## Backup bundles

A bundle contains policies, profiles, triggers, rule groups, blocklists (with
their entries' enabled state) and purpose metadata. It never contains traffic
history, decisions, tokens or keys. Restoring matches things by their IDs
(`pol_…`, `prof_…`, `bl_…`), so restoring twice updates rather than duplicates,
and it does not activate a policy.

`netgraph policy backup -password-file FILE` (or `$NETGRAPH_BUNDLE_PASSWORD`)
encrypts it with AES-256-GCM under a PBKDF2 key; `-sign-key FILE` signs it with
Ed25519 instead. `netgraph policy restore` and `verify` fail closed: a wrong
password, wrong key or changed payload is refused, and with `-verify-key` only
a bundle signed by that key is accepted.

## Firewall export of a version 2 policy

A firewall takes the first rule that matches, so a version 2 policy's rules are
exported in precedence order. `ask` rules, and rules selecting what a firewall
can't see (a device label, app, process or owner), are left out with a warning;
a `domain` exports as the addresses seen for the name and its subdomains.
