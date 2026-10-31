package wifi

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"hash/fnv"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/xen0bit/netgraph/internal/wire"
)

// Config configures a Wi-Fi frame processor.
type Config struct {
	// Keys holds passphrases, WEP keys and PTKs learned from handshakes.
	Keys *Keyring
	// Emit receives observation events. It may be called from the capture
	// goroutine.
	Emit func(wire.Event)
	// Data receives an Ethernet frame rebuilt from a data frame, including
	// frames decrypted with a learned PTK. It lets Wi-Fi capture feed the
	// same IP/DNS/TLS pipeline as a bridge capture.
	Data func(ts time.Time, frame []byte)
	// IncludeData emits one wifi event per data frame. It is off by
	// default: a busy network produces far more data frames than the
	// server needs to see.
	IncludeData bool
	// Dedupe suppresses an identical beacon, probe or authentication for
	// this long (default 10m). Association and handshake frames are never
	// suppressed.
	Dedupe time.Duration
	Logger *slog.Logger
}

// Processor turns radiotap or raw 802.11 frames into events. It is safe for
// concurrent use, because a sensor may capture several monitor interfaces at
// once.
type Processor struct {
	mu    sync.Mutex
	cfg   Config
	keys  *Keyring
	log   *slog.Logger
	seen  map[uint64]time.Time
	frags map[fragKey]*fragState
}

type fragKey struct {
	src, dst, bssid string
	seq             uint16
}

type fragState struct {
	first        *Frame
	parts        [][]byte
	pending      map[uint8][]byte
	next         uint8
	end          uint8
	haveEnd      bool
	total        int
	pendingBytes int
	last         time.Time
}

// NewProcessor returns a processor. A nil Keyring means no network can be
// decrypted, but management frames are still decoded.
func NewProcessor(cfg Config) *Processor {
	if cfg.Keys == nil {
		cfg.Keys = NewKeyring()
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Dedupe <= 0 {
		cfg.Dedupe = 10 * time.Minute
	}
	return &Processor{cfg: cfg, keys: cfg.Keys, log: cfg.Logger, seen: map[uint64]time.Time{}, frags: map[fragKey]*fragState{}}
}

// Keys returns the keyring the processor uses.
func (p *Processor) Keys() *Keyring { return p.keys }

// SetData installs the callback for decapsulated Ethernet frames. It lets a
// sensor create its Wi-Fi processor before its IP processor.
func (p *Processor) SetData(fn func(time.Time, []byte)) { p.cfg.Data = fn }

// Tick drops fragment states that went quiet, so a partial frame from an
// interrupted transmission does not stay around forever.
func (p *Processor) Tick(now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, st := range p.frags {
		if now.Sub(st.last) > 2*time.Second {
			delete(p.frags, k)
		}
	}
	for k, t := range p.seen {
		if now.Sub(t) > 2*p.cfg.Dedupe {
			delete(p.seen, k)
		}
	}
}

// Handle processes one captured frame. radiotap says whether data starts
// with a radiotap header (monitor mode) or the bare 802.11 frame.
func (p *Processor) Handle(ts time.Time, data []byte, radiotap bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	radio := Radio{}
	frame := data
	if radiotap {
		var err error
		radio, frame, err = ParseRadiotap(data)
		if err != nil {
			p.log.Debug("radiotap", "err", err)
			return
		}
		if radio.FCS {
			if len(frame) < 4 {
				return
			}
			want := binary.LittleEndian.Uint32(frame[len(frame)-4:])
			frame = frame[:len(frame)-4]
			if crc32.ChecksumIEEE(frame) != want {
				// Radiotap can mark a bad FCS; either way the frame is
				// not trustworthy.
				return
			}
		}
	}
	f, err := Parse(frame)
	if err != nil {
		p.log.Debug("802.11 frame", "err", err)
		return
	}
	f.Radio = radio
	f.TS = ts
	if radio.DataPad && f.Type == TypeData {
		pad := (f.HeaderLen+3)&^3 - f.HeaderLen
		if pad > len(f.Body) {
			return
		}
		f.Body = f.Body[pad:]
	}
	switch f.Type {
	case TypeManagement:
		p.management(ts, f)
	case TypeData:
		p.data(ts, f)
	}
}

func (p *Processor) management(ts time.Time, f *Frame) {
	switch f.Subtype {
	case SubtypeBeacon, SubtypeProbeResp:
		p.keys.setNetwork(f.BSSID.String(), f.SSID, f.Security)
	case SubtypeAssocReq, SubtypeReassocReq:
		// A hidden network reveals its name in the association request.
		if f.SSID != "" {
			p.keys.setNetwork(f.BSSID.String(), f.SSID, f.Security)
		}
	}
	switch f.Subtype {
	case SubtypeBeacon, SubtypeProbeResp, SubtypeProbeReq, SubtypeAuth, SubtypeAction, SubtypeActionNoAck:
		if p.suppress(ts, f.Kind(), f.BSSID.String(), f.SSID, f.Src.String(), f.Security.String(), strconv.Itoa(f.Radio.Channel)) {
			return
		}
	}
	p.emit(ts, f.WireEvent())
}

// suppress drops a repeated management frame. Access points beacon several
// times a second; the server needs to know the network is still there, not
// every copy. Association and handshake frames bypass this.
func (p *Processor) suppress(ts time.Time, parts ...string) bool {
	h := fnv.New64a()
	for _, s := range parts {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	k := h.Sum64()
	last, ok := p.seen[k]
	if ok && ts.Sub(last) < p.cfg.Dedupe && !ts.Before(last) {
		return true
	}
	p.seen[k] = ts
	if len(p.seen) > 100_000 {
		clear(p.seen)
	}
	return false
}

func (p *Processor) data(ts time.Time, f *Frame) {
	llc := f.Body
	if f.Protected {
		plain, _, err := p.keys.Decrypt(f)
		if errors.Is(err, errRelayed) {
			return
		}
		if err != nil {
			if p.cfg.IncludeData {
				e := f.WireEvent()
				e.Protected, e.Error = true, err.Error()
				p.emit(ts, e)
			}
			return
		}
		llc = plain
	}
	if f.MoreFrag || f.FragNumber != 0 {
		p.fragment(ts, f, llc)
		return
	}
	p.payload(ts, f, llc)
}

// payload handles a complete LLC payload, which may be an A-MSDU aggregate.
func (p *Processor) payload(ts time.Time, f *Frame, llc []byte) {
	if !f.AMSDU() {
		p.msdu(ts, f, f.Dst, f.Src, llc)
		return
	}
	subs, err := splitAMSDU(llc)
	if err != nil {
		if p.cfg.IncludeData {
			e := f.WireEvent()
			e.Protected, e.Decrypted, e.Error = f.Protected, f.Protected, err.Error()
			p.emit(ts, e)
		}
		return
	}
	for _, sf := range subs {
		p.msdu(ts, f, sf.dst, sf.src, sf.llc)
	}
}

// fragment reassembles a fragmented MSDU. Each fragment (including each
// protected fragment) has already been decrypted; the pieces are joined
// before SNAP/LLC handling. A gap drops the partial frame rather than
// handing the network a corrupted packet.
func (p *Processor) fragment(ts time.Time, f *Frame, llc []byte) {
	p.pruneFrags(ts)
	key := fragKey{src: f.Src.String(), dst: f.Dst.String(), bssid: f.BSSID.String(), seq: f.Seq}
	st := p.frags[key]
	if st == nil {
		st = &fragState{first: nil, pending: map[uint8][]byte{}}
		p.frags[key] = st
	}
	st.last = ts
	if f.FragNumber == 0 {
		cp := *f
		st.first = &cp
	}
	if f.FragNumber < st.next {
		return // duplicate of a fragment already joined
	}
	if f.FragNumber > st.next {
		if _, ok := st.pending[f.FragNumber]; !ok {
			st.pending[f.FragNumber] = append([]byte(nil), llc...)
			st.pendingBytes += len(llc)
		}
		if !f.MoreFrag {
			st.end, st.haveEnd = f.FragNumber, true
		}
		if len(st.pending) > 32 || st.pendingBytes+st.total > 64<<10 {
			delete(p.frags, key)
		}
		return
	}
	// The next expected fragment arrived; append it and any successors
	// that were waiting for the gap.
	st.parts = append(st.parts, append([]byte(nil), llc...))
	st.total += len(llc)
	if !f.MoreFrag {
		st.end, st.haveEnd = f.FragNumber, true
	}
	st.next++
	for {
		part, ok := st.pending[st.next]
		if !ok {
			break
		}
		delete(st.pending, st.next)
		st.pendingBytes -= len(part)
		st.parts = append(st.parts, part)
		st.total += len(part)
		st.next++
	}
	if st.total > 64<<10 || len(st.parts) > 32 {
		delete(p.frags, key)
		return
	}
	if !st.haveEnd || st.next <= st.end {
		return
	}
	joined := make([]byte, 0, st.total)
	for _, part := range st.parts {
		joined = append(joined, part...)
	}
	base := *st.first
	delete(p.frags, key)
	p.payload(ts, &base, joined)
}

func (p *Processor) pruneFrags(ts time.Time) {
	if len(p.frags) < 1024 {
		return
	}
	for k, st := range p.frags {
		if ts.Sub(st.last) > 2*time.Second || len(st.parts) > 32 {
			delete(p.frags, k)
		}
	}
}

// msdu handles one LLC payload: a whole data frame, or one subframe of an
// A-MSDU, which carries its own addresses.
func (p *Processor) msdu(ts time.Time, f *Frame, dst, src net.HardwareAddr, llc []byte) {
	etherType, payload := snap(llc)
	if etherType == 0 {
		if p.cfg.IncludeData {
			e := f.WireEvent()
			e.Protected, e.Decrypted, e.Error = f.Protected, f.Protected, "802.11: no SNAP header"
			p.emit(ts, e)
		}
		return
	}
	if etherType == 0x888e {
		// EAPOL is never encrypted at the link layer: the 4-way
		// handshake is how the pairwise key is established.
		if msg, err := ParseEAPOL(payload); err == nil {
			p.eapol(ts, f, msg)
		}
		return
	}
	if p.cfg.IncludeData {
		e := f.WireEvent()
		// A protected frame only gets here once it has been decrypted.
		e.Protected = f.Protected
		e.Decrypted = f.Protected
		e.Bytes = uint64(len(payload))
		p.describeNetwork(e, f)
		p.emit(ts, e)
	}
	if p.cfg.Data != nil {
		if eth := f.Ethernet(dst, src, etherType, payload); eth != nil {
			p.cfg.Data(ts, eth)
		}
	}
}

func (p *Processor) eapol(ts time.Time, f *Frame, msg *EAPOLKey) {
	info := p.keys.ProcessEAPOL(f, msg)
	e := f.WireEvent()
	e.Kind = "handshake"
	e.Protected = false
	e.Decrypted = false
	p.describeNetwork(e, f)
	e.EAPOL = &wire.EAPOL{Message: info.Message, Version: info.Version, Cipher: info.Cipher, Valid: info.Valid, Installed: info.Installed,
		Group: info.Group, GTK: info.GTK}
	if info.Err != nil {
		e.Error = info.Err.Error()
	}
	p.emit(ts, e)
	if info.Installed && len(info.ANonce) == 32 && len(info.SNonce) == 32 && p.cfg.Emit != nil {
		// Ship the public nonces so the server can persist them and
		// hand them to other or restarted sensors. No key, PMK or MIC
		// leaves here; the nonces were broadcast in the clear.
		p.cfg.Emit(wire.Event{Type: wire.TypeWiFiKey, TS: ts, WiFiKey: &wire.WiFiKey{
			BSSID: info.AP, STA: info.STA, SSID: info.SSID,
			ANonce:     hex.EncodeToString(info.ANonce),
			SNonce:     hex.EncodeToString(info.SNonce),
			KeyVersion: info.Version,
		}})
	}
	if g := info.GroupKey; g != nil && p.cfg.Emit != nil {
		// The GTK goes out still wrapped with the client's KEK; a sensor
		// that receives it unwraps it with its own PMK.
		p.cfg.Emit(wire.Event{Type: wire.TypeWiFiGTK, TS: ts, WiFiGTK: g.Wire()})
	}
}

// amsduSubframe is one MSDU of an aggregate.
type amsduSubframe struct {
	dst, src net.HardwareAddr
	llc      []byte
}

// maxAMSDUSubframes bounds the subframes taken from one aggregate. The
// largest A-MSDU (11454 bytes) of minimal subframes is well under it.
const maxAMSDUSubframes = 256

// splitAMSDU splits an A-MSDU payload into its subframes: DA, SA, a
// big-endian length, the LLC payload, then padding to four bytes (except
// after the last). The subframes alias b.
func splitAMSDU(b []byte) ([]amsduSubframe, error) {
	// An A-MSDU whose first DA is an LLC/SNAP header is a plain frame
	// with the (unauthenticated) A-MSDU bit flipped: the FragAttacks
	// injection (CVE-2020-24588). Linux drops these; so does netgraph.
	if len(b) >= 6 && b[0] == 0xaa && b[1] == 0xaa && b[2] == 0x03 && b[3] == 0 && b[4] == 0 && b[5] == 0 {
		return nil, fmt.Errorf("802.11: A-MSDU starts with an LLC header")
	}
	var out []amsduSubframe
	for len(b) > 0 {
		if len(out) == maxAMSDUSubframes {
			return nil, fmt.Errorf("802.11: A-MSDU has too many subframes")
		}
		if len(b) < 14 {
			return nil, fmt.Errorf("802.11: truncated A-MSDU subframe")
		}
		n := int(binary.BigEndian.Uint16(b[12:]))
		if 14+n > len(b) {
			return nil, fmt.Errorf("802.11: A-MSDU subframe length %d", n)
		}
		out = append(out, amsduSubframe{dst: b[0:6], src: b[6:12], llc: b[14 : 14+n]})
		next := (14 + n + 3) &^ 3
		if next >= len(b) {
			break
		}
		b = b[next:]
	}
	return out, nil
}

// snap strips an LLC/SNAP header, returning the EtherType and network
// payload. It returns zero for non-SNAP payloads.
func snap(b []byte) (uint16, []byte) {
	if len(b) < 8 || b[0] != 0xaa || b[1] != 0xaa || b[2] != 0x03 || b[3] != 0 || b[4] != 0 || b[5] != 0 {
		return 0, nil
	}
	return binary.BigEndian.Uint16(b[6:]), b[8:]
}

// AMSDU reports whether a QoS data frame carries an aggregate.
func (f *Frame) AMSDU() bool {
	if !f.QoS {
		return false
	}
	off := 24
	if f.ToDS && f.FromDS {
		off += 6
	}
	if off >= len(f.header) {
		return false
	}
	return f.header[off]&0x80 != 0
}

func (p *Processor) describeNetwork(e *wire.WiFi, f *Frame) {
	if f.BSSID == nil {
		return
	}
	if ssid, sec, ok := p.keys.Network(f.BSSID.String()); ok {
		if e.SSID == "" {
			e.SSID = ssid
		}
		if e.Security == "" {
			e.Security = sec.String()
		}
	}
}

func (p *Processor) emit(ts time.Time, e *wire.WiFi) {
	if p.cfg.Emit != nil && e != nil {
		p.cfg.Emit(wire.Event{Type: wire.TypeWiFi, TS: ts, WiFi: e})
	}
}
