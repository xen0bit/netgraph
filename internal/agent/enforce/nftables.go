// Package enforce contains optional host-agent enforcers. The nftables
// enforcer is opt-in, uses a dedicated table, and is only reached when the
// agent is started with -enforce=nftables.
package enforce

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/xen0bit/netgraph/internal/agent"
)

// Nftables drops connections that an explicit, host-wide deny rule matched,
// in a dedicated inet table it owns and rewrites whole each time. Everything
// else is reported, never enforced:
//
//   - a default (no rule matched): a policy's default egress is usually deny,
//     and enforcing it would cut the host off;
//   - a rule that selects an app, process or owner: nftables can't tell
//     processes apart, so a drop by address would block every program;
//   - allow and ask: there is nothing to install, and nothing can ask.
//
// The netgraph server's own addresses are never dropped, so a policy can't
// cut the agent off from the server that would let someone undo it.
type Nftables struct {
	Table  string
	DryRun bool
	// Protect lists addresses never dropped: the server's.
	Protect []netip.Addr
	// Run runs nft with script on stdin; tests replace it.
	Run     func(ctx context.Context, script string) error
	applied string // the ruleset last installed
}

var tableName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

// NewNftables returns an enforcer using the given table name.
func NewNftables(table string) (*Nftables, error) {
	if table == "" {
		table = "netgraph_agent"
	}
	if !tableName.MatchString(table) {
		return nil, fmt.Errorf("nftables table %q: want lowercase letters, digits and _", table)
	}
	return &Nftables{Table: table}, nil
}

func (n *Nftables) run(ctx context.Context, script string) error {
	if n.Run != nil {
		return n.Run(ctx, script)
	}
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft: %w: %s", err, bytes.TrimSpace(out))
	}
	return nil
}

type drop struct {
	ip    netip.Addr
	proto string // tcp, udp or "" for any
	port  int    // 0 for any
}

func (d drop) rule() string {
	fam := "ip"
	if d.ip.Is6() {
		fam = "ip6"
	}
	r := fam + " daddr " + d.ip.String()
	if d.proto != "" && d.port > 0 {
		r += " " + d.proto + " dport " + fmt.Sprint(d.port)
	}
	return r + " drop"
}

// Apply works out what to drop from this scan's predictions, installs it if
// it changed, and reports what was done for each connection.
func (n *Nftables) Apply(ctx context.Context, conns []agent.Connection) ([]agent.Actual, error) {
	if !tableName.MatchString(n.Table) {
		return nil, fmt.Errorf("nftables table %q is not a valid name", n.Table)
	}
	var drops []drop
	seen := map[drop]bool{}
	out := make([]agent.Actual, 0, len(conns))
	for _, c := range conns {
		a := agent.Actual{Key: c.Key, Rule: c.Rule, Action: "none"}
		switch {
		case c.Predicted != "deny":
			a.Reason = "not denied"
			if c.Predicted == "ask" {
				a.Reason = "would ask; the agent cannot ask"
			}
		case c.Scope != agent.ScopeHost:
			a.Reason = "not enforced: " + scopeReason(c.Scope)
		default:
			ip, err := netip.ParseAddr(c.RemoteIP)
			if err != nil {
				a.Reason = "not enforced: no remote address"
				break
			}
			ip = ip.Unmap()
			if slices.Contains(n.Protect, ip) {
				a.Reason = "not enforced: this is the netgraph server"
				break
			}
			d := drop{ip: ip}
			if p := strings.TrimSuffix(c.Proto, "6"); (p == "tcp" || p == "udp") && c.RemotePort > 0 {
				d.proto, d.port = p, c.RemotePort
			}
			if !seen[d] {
				seen[d] = true
				drops = append(drops, d)
			}
			if n.DryRun {
				a.Reason = "dry run: would drop"
				break
			}
			a.Action, a.Reason = "deny", "dropped by the agent's nftables table"
		}
		out = append(out, a)
	}
	if n.DryRun {
		return out, nil
	}
	slices.SortFunc(drops, func(a, b drop) int {
		if c := a.ip.Compare(b.ip); c != 0 {
			return c
		}
		if a.proto != b.proto {
			return strings.Compare(a.proto, b.proto)
		}
		return a.port - b.port
	})
	script := n.script(drops)
	if script == n.applied {
		return out, nil
	}
	if err := n.run(ctx, script); err != nil {
		for i := range out {
			if out[i].Action == "deny" {
				out[i].Action, out[i].Reason = "none", "not enforced: nft failed"
			}
		}
		return out, err
	}
	n.applied = script
	return out, nil
}

// script replaces the table in one transaction: create it if missing, delete
// it, and create it again with exactly these rules. A rule a policy no longer
// asks for is gone, and so is anything left by an agent that crashed.
func (n *Nftables) script(drops []drop) string {
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {}\ndelete table inet %s\ntable inet %s {\n", n.Table, n.Table, n.Table)
	b.WriteString("\tchain output {\n\t\ttype filter hook output priority 0; policy accept;\n")
	for _, d := range drops {
		b.WriteString("\t\t" + d.rule() + "\n")
	}
	b.WriteString("\t}\n}\n")
	return b.String()
}

func scopeReason(scope string) string {
	switch scope {
	case agent.ScopeProcess:
		return "the rule selects a program, and nftables can't tell programs apart"
	case agent.ScopeDefault:
		return "no rule matched; a policy's default is never enforced"
	}
	return "the rule can't be expressed for this host"
}

// Close removes the dedicated table, leaving the host as it was.
func (n *Nftables) Close() error {
	if n.DryRun || n.applied == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	n.applied = ""
	return n.run(ctx, fmt.Sprintf("table inet %s {}\ndelete table inet %s\n", n.Table, n.Table))
}
