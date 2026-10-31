package capture

import (
	"errors"
	"log/slog"
	"sync"
	"time"
)

// ErrClosed is returned by Reconnect after Close or Interrupt.
var ErrClosed = errors.New("capture: source closed")

// Reconnect wraps a live source and reopens it after a read error. An
// interface can disappear and return (a bridge is recreated, a USB adapter
// is unplugged, or the kernel resets the ring); without this the whole
// sensor would exit and stop watching every other interface.
type Reconnect struct {
	name string
	open func() (Source, error)
	log  *slog.Logger

	mu   sync.Mutex
	src  Source
	link int

	done     chan struct{}
	doneOnce sync.Once
	min, max time.Duration
	// OnReopen is called after a successful reopen, so the sensor can emit
	// a fresh hello with the interface's new link/addresses.
	OnReopen func()
}

// NewReconnect wraps first and reopens through open. open is called again
// with the original interface specification, so an address/CIDR can resolve
// to a renamed interface.
func NewReconnect(first Source, open func() (Source, error), log *slog.Logger) *Reconnect {
	if log == nil {
		log = slog.Default()
	}
	return &Reconnect{name: first.Name(), open: open, log: log, src: first, link: first.LinkType(),
		done: make(chan struct{}), min: time.Second, max: 30 * time.Second}
}

func (r *Reconnect) Name() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.name
}

func (r *Reconnect) LinkType() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.link
}

func (r *Reconnect) Stats() (uint64, uint64) {
	r.mu.Lock()
	src := r.src
	r.mu.Unlock()
	if src == nil {
		return 0, 0
	}
	return src.Stats()
}

// Interrupt wakes a ReadPacket that is waiting to reopen. It is safe to call
// from the runner before it waits for the reader goroutine.
func (r *Reconnect) Interrupt() {
	r.doneOnce.Do(func() { close(r.done) })
}

func (r *Reconnect) Close() error {
	r.Interrupt()
	r.mu.Lock()
	src := r.src
	r.src = nil
	r.mu.Unlock()
	if src != nil {
		return src.Close()
	}
	return nil
}

func (r *Reconnect) ReadPacket() ([]byte, time.Time, error) {
	backoff := r.min
	for {
		select {
		case <-r.done:
			return nil, time.Time{}, ErrClosed
		default:
		}
		r.mu.Lock()
		src := r.src
		r.mu.Unlock()
		if src == nil {
			var err error
			src, err = r.open()
			if err != nil {
				r.log.Warn("reopen capture interface", "iface", r.name, "err", err, "retry", backoff)
				if !r.wait(backoff) {
					return nil, time.Time{}, ErrClosed
				}
				if backoff < r.max {
					backoff = min(backoff*2, r.max)
				}
				continue
			}
			r.mu.Lock()
			r.name, r.src, r.link = src.Name(), src, src.LinkType()
			r.mu.Unlock()
			backoff = r.min
			r.log.Info("reopened capture interface", "iface", src.Name(), "link", src.LinkType())
			if r.OnReopen != nil {
				r.OnReopen()
			}
		}
		data, ts, err := src.ReadPacket()
		if err == nil {
			return data, ts, nil
		}
		if errors.Is(err, ErrTimeout) {
			return nil, time.Time{}, err
		}
		if errors.Is(err, ErrClosed) {
			return nil, time.Time{}, ErrClosed
		}
		select {
		case <-r.done:
			return nil, time.Time{}, ErrClosed
		default:
		}
		r.log.Warn("capture read failed; reopening", "iface", r.name, "err", err)
		r.mu.Lock()
		if r.src == src {
			_ = src.Close()
			r.src = nil
		}
		r.mu.Unlock()
		if !r.wait(backoff) {
			return nil, time.Time{}, ErrClosed
		}
		if backoff < r.max {
			backoff = min(backoff*2, r.max)
		}
	}
}

func (r *Reconnect) wait(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-r.done:
		return false
	case <-t.C:
		return true
	}
}
