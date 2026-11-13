package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/xen0bit/netgraph/internal/dnsserver"
	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/sources"
	"github.com/xen0bit/netgraph/internal/store"
	"github.com/xen0bit/netgraph/internal/wire"
)

const (
	// dnsRulesEvery is how often the store is asked whether the rules
	// changed (a cheap fingerprint); a change through the API asks at once.
	dnsRulesEvery = 10 * time.Second
	// dnsClientsEvery is how often who holds which address is reread.
	dnsClientsEvery = 30 * time.Second
)

// dnsControl runs netgraph's DNS server and keeps what it knows current: the
// rules and lists, and which device holds which address.
type dnsControl struct {
	srv     *dnsserver.Server
	st      *store.Store
	log     *slog.Logger
	reload  chan struct{}
	clients atomic.Pointer[map[netip.Addr]store.DNSClient]
}

type dnsFlags struct {
	listen, allow, upstreamFile, blockMode string
}

func newDNSControl(f dnsFlags, st *store.Store, sink sources.Sink, local []netip.Prefix, log *slog.Logger) (*dnsControl, error) {
	var ups []dnsserver.Upstream
	var err error
	switch {
	case f.upstreamFile != "":
		ups, err = dnsserver.ReadUpstreams(f.upstreamFile)
	case os.Getenv("NETGRAPH_DNS_UPSTREAM") != "":
		ups, err = dnsserver.ParseUpstreams(os.Getenv("NETGRAPH_DNS_UPSTREAM"))
	default:
		return nil, fmt.Errorf("-dns-listen needs upstream resolvers: -dns-upstream-file or $NETGRAPH_DNS_UPSTREAM")
	}
	if err != nil {
		return nil, fmt.Errorf("dns upstreams: %w", err)
	}
	allow, err := parsePrefixes("-dns-allow", f.allow)
	if err != nil {
		return nil, err
	}
	c := &dnsControl{st: st, log: log, reload: make(chan struct{}, 1)}
	pub := sources.NewPublisher(store.DNSServerSensor, local, sink, log)
	c.srv, err = dnsserver.New(dnsserver.Config{
		Listen: f.listen, Allow: allow, Upstreams: ups, BlockMode: f.blockMode, Log: log,
		Client: c.client,
		// The recorder is one goroutine, as Publisher.Send needs.
		Record: func(ctx context.Context, evs []wire.Event) { pub.Send(ctx, evs) },
	})
	if err != nil {
		return nil, err
	}
	st.SetDNSSelf(selfAddrs(f.listen))
	return c, nil
}

// selfAddrs are the addresses a listen address answers on: itself, or every
// interface's when it names none.
func selfAddrs(listen string) []netip.Addr {
	host, _, err := net.SplitHostPort(listen)
	if err == nil && host != "" {
		if a, err := netip.ParseAddr(host); err == nil && !a.IsUnspecified() {
			return []netip.Addr{a.Unmap()}
		}
	}
	var out []netip.Addr
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			out = append(out, p.Addr().Unmap())
		}
	}
	return out
}

func (c *dnsControl) client(a netip.Addr) dnsserver.Client {
	m := c.clients.Load()
	if m == nil {
		return dnsserver.Client{}
	}
	dc := (*m)[a.Unmap()]
	return dnsserver.Client{MAC: dc.MAC, Groups: dc.Groups}
}

func (c *dnsControl) Status() *model.DNSServerStatus { return c.srv.Status() }

func (c *dnsControl) Reload() {
	select {
	case c.reload <- struct{}{}:
	default:
	}
}

// Run serves DNS and keeps its rules and clients current until ctx ends.
func (c *dnsControl) Run(ctx context.Context) error {
	last := ""
	refresh := func(force bool) {
		fp, err := c.st.DNSFingerprint(ctx)
		if err != nil {
			c.srv.SetRules(nil, err)
			return
		}
		if fp == last && !force {
			return
		}
		lists, err := c.st.DNSLists(ctx)
		if err != nil {
			c.srv.SetRules(nil, err)
			return
		}
		rules, err := c.st.DNSRules(ctx)
		if err != nil {
			c.srv.SetRules(nil, err)
			return
		}
		in := make([]dnsserver.List, len(lists))
		for i, l := range lists {
			in[i] = dnsserver.List{Name: l.Name, Entries: l.Entries}
		}
		r := dnsserver.BuildRules(in, rules)
		c.srv.SetRules(r, nil)
		last = fp
		c.log.Info("dns rules", "rules", r.Count, "list_entries", r.Entries)
	}
	clients := func() {
		m, err := c.st.DNSClients(ctx)
		if err != nil {
			c.log.Warn("dns clients", "err", err)
			return
		}
		c.clients.Store(&m)
	}
	refresh(true)
	clients()
	go func() {
		rt, ct := time.NewTicker(dnsRulesEvery), time.NewTicker(dnsClientsEvery)
		defer rt.Stop()
		defer ct.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-rt.C:
				refresh(false)
			case <-c.reload:
				// Something changed through the API: rebuild whatever the
				// fingerprint says, as a list's new entries may count the same.
				refresh(true)
				clients() // a device's groups may be what changed
			case <-ct.C:
				clients()
			}
		}
	}()
	err := c.srv.Run(ctx)
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "permission denied") {
		return fmt.Errorf("%w (port 53 needs CAP_NET_BIND_SERVICE, or listen on a port above 1023)", err)
	}
	return err
}
