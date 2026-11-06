// Package enforce contains optional host-agent enforcers. The nftables
// enforcer is opt-in, uses a dedicated table, and is only reached when the
// agent is started with -enforce=nftables.
package enforce

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"

	"github.com/xen0bit/netgraph/internal/agent"
)

// Nftables applies deny predictions to a dedicated inet table. Allow and ask
// predictions are reported but not installed.
type Nftables struct {
	Table  string
	DryRun bool
	Run    func(context.Context, ...string) error // tests replace this
}

// NewNftables returns an enforcer using the given table name.
func NewNftables(table string) *Nftables {
	if table == "" {
		table = "netgraph_agent"
	}
	return &Nftables{Table: table}
}

func (n *Nftables) command(ctx context.Context, args ...string) error {
	if n.DryRun {
		return nil
	}
	if n.Run != nil {
		return n.Run(ctx, args...)
	}
	cmd := exec.CommandContext(ctx, "nft", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Apply installs drop rules for denied remote addresses and reports the
// actual result for every connection. It does not claim to have enforced
// allow or ask decisions.
func (n *Nftables) Apply(ctx context.Context, conns []agent.Connection) ([]agent.Actual, error) {
	if n.Table == "" {
		n.Table = "netgraph_agent"
	}
	if err := n.command(ctx, "add", "table", "inet", n.Table); err != nil {
		return nil, err
	}
	if err := n.command(ctx, "add", "chain", "inet", n.Table, "output",
		"{", "type", "filter", "hook", "output", "priority", "0", ";", "}"); err != nil {
		return nil, err
	}
	var out []agent.Actual
	seen := map[string]bool{}
	for _, c := range conns {
		a := agent.Actual{Key: c.Key, Rule: c.Rule, Reason: c.Reason, At: 0}
		switch c.Predicted {
		case "deny":
			ip := c.RemoteIP
			if _, err := netip.ParseAddr(ip); err == nil && !seen[ip] {
				seen[ip] = true
				fam := "ip"
				if strings.Contains(ip, ":") {
					fam = "ip6"
				}
				if err := n.command(ctx, "add", "rule", "inet", n.Table, "output", fam, "daddr", ip, "drop"); err != nil {
					return out, err
				}
			}
			a.Action = "deny"
		case "ask":
			a.Action = "ask"
		default:
			a.Action = "none"
		}
		out = append(out, a)
	}
	return out, nil
}

// Close removes the dedicated table, leaving the host as it was.
func (n *Nftables) Close() error {
	if n.Table == "" {
		return nil
	}
	return n.command(context.Background(), "delete", "table", "inet", n.Table)
}
