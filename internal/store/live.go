package store

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/xen0bit/netgraph/internal/model"
)

// LiveEvent is a one-line summary of something just ingested, for the
// live feeds (SSE) of the UIs.
type LiveEvent struct {
	Type   string `json:"type"`
	TS     int64  `json:"ts"`
	Device int64  `json:"-"`
	Entity string `json:"entity,omitempty"` // the device's entity ID, when someone is listening
	Label  string `json:"label,omitempty"`
	Detail string `json:"detail"`
}

// broker fans live events out to subscribers. A subscriber that falls
// behind loses events rather than slowing ingest.
type broker struct {
	mu   sync.Mutex
	subs map[chan []LiveEvent]struct{}
}

func newBroker() *broker { return &broker{subs: map[chan []LiveEvent]struct{}{}} }

func (b *broker) listening() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.subs) > 0
}

// nameLive fills in which device each event is about. Only when someone is
// listening: ingest must not pay for a feed nobody reads. A failure leaves the
// events unnamed, which a feed can survive and ingest should not fail over.
func (s *Store) nameLive(ctx context.Context, evs []LiveEvent) {
	if len(evs) == 0 || !s.sub.listening() {
		return
	}
	ids := map[int64]bool{}
	for _, e := range evs {
		if e.Device != 0 {
			ids[e.Device] = true
		}
	}
	if len(ids) == 0 {
		return
	}
	list := make([]int64, 0, len(ids))
	for id := range ids {
		list = append(list, id)
	}
	rows, err := s.r.QueryContext(ctx, `SELECT id, key, label, attrs FROM entities WHERE kind = 'device' AND id IN (`+idList(list)+`)`)
	if err != nil {
		return
	}
	defer rows.Close()
	type named struct{ id, label string }
	names := map[int64]named{}
	for rows.Next() {
		var id int64
		var key, label, attrs string
		if rows.Scan(&id, &key, &label, &attrs) == nil {
			var a map[string]string
			_ = json.Unmarshal([]byte(attrs), &a)
			names[id] = named{model.EntityID(model.KindDevice, key), deviceLabel(key, label, a)}
		}
	}
	for i := range evs {
		if n, ok := names[evs[i].Device]; ok {
			evs[i].Entity, evs[i].Label = n.id, n.label
		}
	}
}

func (b *broker) publish(evs []LiveEvent) {
	if len(evs) == 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs {
		select {
		case ch <- evs:
		default:
		}
	}
}

// Subscribe returns a channel of ingested-event batches and a function
// that ends the subscription.
func (s *Store) Subscribe() (<-chan []LiveEvent, func()) {
	ch := make(chan []LiveEvent, 16)
	s.sub.mu.Lock()
	s.sub.subs[ch] = struct{}{}
	s.sub.mu.Unlock()
	return ch, func() {
		s.sub.mu.Lock()
		delete(s.sub.subs, ch)
		s.sub.mu.Unlock()
	}
}
