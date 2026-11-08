//go:build linux

// Package bpf loads netgraph-agent's connection events (src/conn.c): the
// kernel reports each TCP connection as it opens or is accepted, and each UDP
// flow and ICMP echo as a process sends, with the process behind it. A
// connection that lasts milliseconds is named; polling /proc misses it.
//
// It needs CAP_BPF and CAP_PERFMON (or root), and a kernel with BTF and BPF
// trampolines (fentry), and bpf_get_func_ret: 5.17 on amd64, 6.0 on arm64.
// It only reads.
package bpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// Kinds of event.
const (
	KindConnect = 1 // an outbound TCP connection
	KindAccept  = 2 // an accepted TCP connection
	KindSend    = 3 // a UDP datagram or an ICMP echo request sent
)

// Event is one connection a process opened, accepted or sent on.
type Event struct {
	Start  uint64 // the process's start, ns after boot
	Ino    uint64 // the socket's inode
	PID    int
	PPID   int
	UID    int
	Family int // 2 or 10
	Proto  int // 6, 17, 1 or 58
	Kind   int
	// Ports in host order; an ICMP echo's identifier is SPort.
	SPort, DPort uint16
	Src, Dst     netip.Addr
	Comm         string
}

// eventSize is struct event's size in src/conn.c, padding included.
const eventSize = 88

// Parse decodes one record of the ring buffer.
func Parse(b []byte) (Event, bool) {
	if len(b) < eventSize {
		return Event{}, false
	}
	ne := binary.NativeEndian
	e := Event{
		Start: ne.Uint64(b[0:]), Ino: ne.Uint64(b[8:]),
		PID: int(ne.Uint32(b[16:])), PPID: int(ne.Uint32(b[20:])), UID: int(ne.Uint32(b[24:])),
		Family: int(ne.Uint16(b[28:])), Proto: int(b[30]), Kind: int(b[31]),
		SPort: ne.Uint16(b[32:]), DPort: ne.Uint16(b[34:]),
	}
	switch e.Family {
	case 2:
		e.Src, e.Dst = netip.AddrFrom4([4]byte(b[36:40])), netip.AddrFrom4([4]byte(b[52:56]))
	case 10:
		e.Src, e.Dst = netip.AddrFrom16([16]byte(b[36:52])).Unmap(), netip.AddrFrom16([16]byte(b[52:68])).Unmap()
	default:
		return Event{}, false
	}
	comm := b[68:84]
	if i := bytes.IndexByte(comm, 0); i >= 0 {
		comm = comm[:i]
	}
	e.Comm = strings.ToValidUTF8(string(comm), "?")
	if e.PID <= 0 || e.Kind < KindConnect || e.Kind > KindSend {
		return Event{}, false
	}
	return e, true
}

// Reader delivers events until it is closed.
type Reader struct {
	coll    *ebpf.Collection
	links   []link.Link
	rd      *ringbuf.Reader
	missing []string
	once    sync.Once
}

// optional programs: without them TCP is still named.
var optional = map[string]string{
	"on_udp4": "IPv4 UDP", "on_udp6": "IPv6 UDP", "on_ping4": "IPv4 ping sockets", "on_ping6": "IPv6 ping sockets",
	"on_raw4": "IPv4 raw ICMP", "on_raw6": "IPv6 raw ICMP",
}

// Open loads and attaches the programs, reporting sockets in the network
// namespace with inode netns (0: every namespace).
func Open(netns uint32) (*Reader, error) {
	_ = rlimit.RemoveMemlock() // needed before 5.11; fails harmlessly without the right
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		return nil, err
	}
	r := &Reader{}
	for {
		coll, err := ebpf.NewCollection(spec)
		if err == nil {
			r.coll = coll
			break
		}
		dropped := false
		for name, what := range optional {
			if _, ok := spec.Programs[name]; ok && strings.Contains(err.Error(), name) {
				delete(spec.Programs, name)
				r.missing = append(r.missing, what)
				dropped = true
			}
		}
		if !dropped {
			return nil, explain(err)
		}
	}
	if err := r.coll.Maps["config"].Put(uint32(0), netns); err != nil {
		r.Close()
		return nil, err
	}
	for name, p := range r.coll.Programs {
		l, err := link.AttachTracing(link.TracingOptions{Program: p})
		if err != nil {
			if what, ok := optional[name]; ok {
				r.missing = append(r.missing, what)
				continue
			}
			r.Close()
			return nil, fmt.Errorf("attach %s: %w", name, explain(err))
		}
		r.links = append(r.links, l)
	}
	r.rd, err = ringbuf.NewReader(r.coll.Maps["events"])
	if err != nil {
		r.Close()
		return nil, err
	}
	return r, nil
}

func explain(err error) error {
	if errors.Is(err, os.ErrPermission) || errors.Is(err, ebpf.ErrNotSupported) {
		return fmt.Errorf("%w (BPF events need CAP_BPF and CAP_PERFMON, and a kernel with BTF and fentry)", err)
	}
	return err
}

// Missing says what this kernel couldn't hook, if anything.
func (r *Reader) Missing() []string { return r.missing }

// Read waits for the next event. It returns os.ErrClosed once closed.
func (r *Reader) Read() (Event, error) {
	for {
		rec, err := r.rd.Read()
		if err != nil {
			return Event{}, err
		}
		if e, ok := Parse(rec.RawSample); ok {
			return e, nil
		}
	}
}

// Close detaches everything.
func (r *Reader) Close() error {
	r.once.Do(func() {
		if r.rd != nil {
			r.rd.Close()
		}
		for _, l := range r.links {
			l.Close()
		}
		if r.coll != nil {
			r.coll.Close()
		}
	})
	return nil
}
