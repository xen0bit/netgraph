package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strconv"

	"github.com/xen0bit/netgraph/internal/model"
)

type dnsBackend interface {
	DNSRules(context.Context) ([]model.DNSRule, error)
	SaveDNSRule(context.Context, *model.DNSRule) (*model.DNSRule, error)
	DeleteDNSRule(context.Context, int64) error
	DNSStats(context.Context, model.Filter) (*model.DNSStats, error)
}

const dnsUsage = `usage: netgraph dns <command>

  rules                    the DNS server's rules
  block NAME [-device MAC] refuse NAME and its subdomains (for one device)
  allow NAME [-device MAC] answer NAME even if a list blocks it; allow '*' -device MAC turns filtering off for it
  delete ID                remove a rule
  stats [-from -24h]       lookups and refusals: the busiest names and clients
  status                   the running server's listeners, upstreams and counters (-server only)

Rules apply to netgraph serve -dns-listen; with -db they are written to the
database, and a running server picks them up within seconds.
`

func runDNS(args []string) error {
	if len(args) == 0 {
		fmt.Print(dnsUsage)
		return errors.New("missing dns command")
	}
	cmd, args := args[0], args[1:]
	fs := flag.NewFlagSet("dns "+cmd, flag.ContinueOnError)
	var b backendFlags
	b.register(fs)
	var device, group, note string
	var f filterFlags
	if cmd == "stats" {
		f.register(fs) // its -device filters the stats
	} else {
		fs.StringVar(&device, "device", "", "block or allow: only for this device (its MAC)")
		fs.StringVar(&group, "group", "", "block or allow: only for devices in this group")
		fs.StringVar(&note, "note", "", "block or allow: why")
	}
	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	ctx := context.Background()
	if cmd == "status" {
		if b.server == "" {
			return errors.New("dns status asks a running server: give -server")
		}
		c, closeFn, err := b.open()
		if err != nil {
			return err
		}
		defer closeFn()
		s, ok := c.(interface {
			DNSServer(context.Context) (*model.DNSServerStatus, error)
		})
		if !ok {
			return errors.New("this backend can't report the DNS server")
		}
		st, err := s.DNSServer(ctx)
		if err != nil {
			return err
		}
		return encode(st)
	}
	write := cmd == "block" || cmd == "allow" || cmd == "delete"
	var be model.Backend
	var closeFn func()
	var err error
	if write {
		be, closeFn, err = b.openWritable()
	} else {
		be, closeFn, err = b.open()
	}
	if err != nil {
		return err
	}
	defer closeFn()
	d, ok := be.(dnsBackend)
	if !ok {
		return errors.New("this backend can't do DNS rules")
	}
	switch cmd {
	case "rules":
		out, err := d.DNSRules(ctx)
		if err != nil {
			return err
		}
		return encode(out)
	case "block", "allow":
		if fs.NArg() != 1 {
			return fmt.Errorf("usage: netgraph dns %s NAME [-device MAC | -group NAME]", cmd)
		}
		r := &model.DNSRule{Scope: model.DNSScopeAll, Action: cmd, Pattern: fs.Arg(0), Note: note}
		switch {
		case device != "" && group != "":
			return errors.New("give -device or -group, not both")
		case device != "":
			r.Scope, r.ScopeValue = model.DNSScopeDevice, device
		case group != "":
			r.Scope, r.ScopeValue = model.DNSScopeGroup, group
		}
		out, err := d.SaveDNSRule(ctx, r)
		if err != nil {
			return err
		}
		return encode(out)
	case "delete":
		if fs.NArg() != 1 {
			return errors.New("usage: netgraph dns delete ID")
		}
		id, err := strconv.ParseInt(fs.Arg(0), 10, 64)
		if err != nil {
			return fmt.Errorf("%q is not a rule ID", fs.Arg(0))
		}
		return d.DeleteDNSRule(ctx, id)
	case "stats":
		flt, err := f.filter()
		if err != nil {
			return err
		}
		out, err := d.DNSStats(ctx, flt)
		if err != nil {
			return err
		}
		return encode(out)
	}
	fmt.Print(dnsUsage)
	return fmt.Errorf("dns: %q is not a command", cmd)
}
