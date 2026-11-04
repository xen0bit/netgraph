package conntrack

import (
	"context"
	"log/slog"
	"time"

	"github.com/xen0bit/netgraph/internal/wire"
)

// Reader reads the table: Dump on Linux.
type Reader func() (entries []Entry, complete bool, err error)

// Runner reads the table on a schedule and emits what changed.
type Runner struct {
	Tracker Tracker
	Read    Reader
	Emit    func(wire.Event)
	Every   time.Duration
	Log     *slog.Logger
}

// Check reads the table once, to find out at startup whether it can be read at all.
func (r *Runner) Check() error {
	_, _, err := r.Read()
	return err
}

// Run reads until ctx ends, then ends what's open.
func (r *Runner) Run(ctx context.Context) {
	if r.Every <= 0 {
		r.Every = 10 * time.Second
	}
	if r.Log == nil {
		r.Log = slog.Default()
	}
	t := time.NewTicker(r.Every)
	defer t.Stop()
	warned, failing := false, false
	for {
		entries, complete, err := r.Read()
		switch {
		case err != nil:
			if !failing { // it may stay this way: once is enough
				r.Log.Warn("conntrack: couldn't read the table", "err", err)
				failing = true
			}
		default:
			failing = false
			if !warned && len(entries) > 0 && !entries[0].Counted {
				r.Log.Warn("conntrack: the kernel isn't counting bytes, so connections will show with no volume; set net.netfilter.nf_conntrack_acct=1")
				warned = true
			}
			r.send(r.Tracker.Update(entries, complete, time.Now()))
		}
		select {
		case <-ctx.Done():
			r.send(r.Tracker.Close(time.Now()))
			return
		case <-t.C:
		}
	}
}

func (r *Runner) send(flows []wire.Flow) {
	for i := range flows {
		f := flows[i]
		r.Emit(wire.Event{Type: wire.TypeFlow, TS: f.End, Flow: &f})
	}
}
