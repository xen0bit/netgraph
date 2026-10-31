package capture

import (
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"
)

type fakeSource struct {
	name string
	link int
	err  error
	data []byte
	ts   time.Time
	read atomic.Int64
	done atomic.Bool
}

func (f *fakeSource) Name() string  { return f.name }
func (f *fakeSource) LinkType() int { return f.link }
func (f *fakeSource) ReadPacket() ([]byte, time.Time, error) {
	f.read.Add(1)
	if f.err != nil {
		return nil, time.Time{}, f.err
	}
	if f.done.Load() {
		return nil, time.Time{}, ErrClosed
	}
	return f.data, f.ts, nil
}
func (f *fakeSource) Stats() (uint64, uint64) { return 1, 2 }
func (f *fakeSource) Close() error            { f.done.Store(true); return nil }

func TestReconnectAfterReadError(t *testing.T) {
	first := &fakeSource{name: "br-lan", link: LinkEthernet, err: io.ErrUnexpectedEOF}
	second := &fakeSource{name: "br-lan", link: LinkEthernet, data: []byte{1, 2, 3}, ts: time.Unix(1, 0)}
	var reopened atomic.Int64
	r := NewReconnect(first, func() (Source, error) {
		reopened.Add(1)
		return second, nil
	}, nil)
	r.min, r.max = time.Millisecond, time.Millisecond
	data, _, err := r.ReadPacket()
	if err != nil || len(data) != 3 {
		t.Fatalf("read after reopen: %x %v", data, err)
	}
	if reopened.Load() != 1 || r.LinkType() != LinkEthernet {
		t.Fatalf("reopened=%d link=%d", reopened.Load(), r.LinkType())
	}
	r.Close()
}

func TestReconnectInterrupt(t *testing.T) {
	first := &fakeSource{name: "br-lan", link: LinkEthernet, err: errors.New("down")}
	r := NewReconnect(first, func() (Source, error) { return nil, errors.New("still down") }, nil)
	r.min, r.max = time.Hour, time.Hour
	errc := make(chan error, 1)
	go func() {
		_, _, err := r.ReadPacket()
		errc <- err
	}()
	time.Sleep(10 * time.Millisecond)
	r.Interrupt()
	select {
	case err := <-errc:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("ReadPacket = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ReadPacket did not stop after Interrupt")
	}
}
