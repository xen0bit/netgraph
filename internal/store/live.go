package store

import "sync"

// LiveEvent is a one-line summary of something just ingested, for the
// live feeds (SSE) of the UIs.
type LiveEvent struct {
	Type   string `json:"type"`
	TS     int64  `json:"ts"`
	Device int64  `json:"-"`
	Detail string `json:"detail"`
}

// broker fans live events out to subscribers. A subscriber that falls
// behind loses events rather than slowing ingest.
type broker struct {
	mu   sync.Mutex
	subs map[chan []LiveEvent]struct{}
}

func newBroker() *broker { return &broker{subs: map[chan []LiveEvent]struct{}{}} }

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
