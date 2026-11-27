package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/policy/blocklist"
	"github.com/xen0bit/netgraph/internal/store"
)

// blocklistCheckEvery is how often a due list is looked for. Each list runs
// on its own UpdateInterval; this only bounds how late one can be.
const blocklistCheckEvery = time.Minute

// runBlocklistRefresh updates each enabled blocklist whose UpdateInterval
// has passed. A filter list that never updates goes stale silently, which is
// the opposite of what a DNS server using it is for. Lists are fetched one
// at a time, on this goroutine, so a slow feed holds up the others but never
// the server.
func runBlocklistRefresh(ctx context.Context, st *store.Store, log *slog.Logger) {
	f := &blocklist.Fetcher{}
	tick := func() {
		lists, err := st.Blocklists(ctx)
		if err != nil {
			if ctx.Err() == nil {
				log.Warn("blocklist refresh: reading lists", "err", err)
			}
			return
		}
		now := time.Now().UnixMilli()
		for _, b := range lists {
			if !b.Enabled || b.URL == "" || !blocklistDue(b, now) {
				continue
			}
			if _, err := st.UpdateBlocklist(ctx, b.ID, f); err != nil {
				if ctx.Err() == nil {
					log.Warn("blocklist refresh", "list", b.Name, "err", err)
				}
				continue
			}
			log.Info("blocklist refreshed", "list", b.Name)
		}
	}
	tick()
	t := time.NewTicker(blocklistCheckEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			tick()
		}
	}
}

// blocklistRetry is the longest a failed list waits before it is tried again.
const blocklistRetry = int64(time.Hour / time.Millisecond)

// blocklistDue says whether a list's UpdateInterval has passed since it was
// last fetched. Now is unix ms; UpdateInterval is seconds, and 0 means the
// store's default of a day. A list whose last attempt failed waits the
// interval or an hour, whichever is less, from that failure: a dead feed must
// not be fetched every minute, and each failure changes the list's modified
// time, which makes the DNS server reload its rules.
func blocklistDue(b model.Blocklist, now int64) bool {
	every := b.UpdateInterval
	if every <= 0 {
		every = 86400
	}
	every *= 1000
	if b.LastFailure > b.LastSuccess && now-b.LastFailure < min(every, blocklistRetry) {
		return false
	}
	return b.LastSuccess <= 0 || now-b.LastSuccess >= every
}
