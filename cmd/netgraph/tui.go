package main

import (
	"flag"

	"github.com/xen0bit/netgraph/internal/buildinfo"
	"github.com/xen0bit/netgraph/internal/tui"
)

func runTUI(args []string) error {
	fs := flag.NewFlagSet("tui", flag.ContinueOnError)
	var b backendFlags
	var f filterFlags
	b.register(fs)
	f.register(fs)
	live := fs.Bool("live", false, "follow now, refreshing every 5s")
	if err := fs.Parse(args); err != nil {
		return err
	}
	filter, err := f.filter()
	if err != nil {
		return err
	}
	be, closeFn, err := b.open()
	if err != nil {
		return err
	}
	defer closeFn()
	source := b.db
	if b.server != "" {
		source = b.server
	}
	return tui.Run(tui.Options{
		Backend: be, Source: source, Filter: filter, Span: filter.To.Sub(filter.From), Live: *live,
		Version: buildinfo.Version,
	})
}
