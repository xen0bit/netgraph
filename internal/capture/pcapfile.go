package capture

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"time"
)

// A small reader for pcap and pcapng. gopacket's pcapgo would do, but it
// imports gopacket/layers, which more than doubles the sensor binary; the
// sensor only needs frames, timestamps and link types.

// maxSnap bounds a record's captured length; anything larger is corrupt.
const maxSnap = 1 << 18

var errFormat = errors.New("capture: not a pcap or pcapng file")

// OpenFile opens a pcap or pcapng file.
func OpenFile(path string) (Source, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	s, err := NewReader(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	s.name, s.closer = path, f
	return s, nil
}

// Reader reads frames from a pcap or pcapng stream.
type Reader struct {
	name   string
	closer io.Closer
	r      *bufio.Reader
	ng     bool
	bo     binary.ByteOrder
	n      uint64

	// pcap
	nanos bool
	link  int

	// pcapng: per-interface link type and timestamp unit
	ifaces []ngIface
	buf    []byte
}

type ngIface struct {
	link int
	unit float64 // seconds per timestamp tick
}

// NewReader reads the file header from r.
func NewReader(r io.Reader) (*Reader, error) {
	br := bufio.NewReaderSize(r, 1<<20)
	magic, err := br.Peek(4)
	if err != nil {
		return nil, errFormat
	}
	s := &Reader{r: br}
	switch {
	case magic[0] == 0x0a && magic[1] == 0x0d && magic[2] == 0x0d && magic[3] == 0x0a:
		s.ng = true
		return s, s.readSHB()
	}
	var hdr [24]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return nil, errFormat
	}
	switch binary.LittleEndian.Uint32(hdr[:]) {
	case 0xa1b2c3d4:
		s.bo = binary.LittleEndian
	case 0xa1b23c4d:
		s.bo, s.nanos = binary.LittleEndian, true
	case 0xd4c3b2a1:
		s.bo = binary.BigEndian
	case 0x4d3cb2a1:
		s.bo, s.nanos = binary.BigEndian, true
	default:
		return nil, errFormat
	}
	s.link = int(s.bo.Uint32(hdr[20:]) & 0x0fffffff)
	return s, nil
}

func (s *Reader) Name() string { return s.name }

// LinkType is the link type of the packet last read (pcapng files can mix
// interfaces), or of the file before the first read.
func (s *Reader) LinkType() int { return s.link }

func (s *Reader) Stats() (uint64, uint64) { return s.n, 0 }

func (s *Reader) Close() error {
	if s.closer != nil {
		return s.closer.Close()
	}
	return nil
}

// ReadPacket returns the next frame; io.EOF at the end. A file cut off
// mid-record also ends with io.EOF: a capture interrupted while writing is
// the common case, not an error.
func (s *Reader) ReadPacket() ([]byte, time.Time, error) {
	if s.ng {
		return s.readNG()
	}
	var h [16]byte
	if _, err := io.ReadFull(s.r, h[:]); err != nil {
		return nil, time.Time{}, eof(err)
	}
	incl := s.bo.Uint32(h[8:])
	if incl > maxSnap {
		return nil, time.Time{}, fmt.Errorf("capture: record of %d bytes", incl)
	}
	data := s.grow(int(incl))
	if _, err := io.ReadFull(s.r, data); err != nil {
		return nil, time.Time{}, eof(err)
	}
	sec, frac := int64(s.bo.Uint32(h[0:])), int64(s.bo.Uint32(h[4:]))
	if !s.nanos {
		frac *= 1000
	}
	s.n++
	return data, time.Unix(sec, frac).UTC(), nil
}

func (s *Reader) grow(n int) []byte {
	if cap(s.buf) < n {
		s.buf = make([]byte, n)
	}
	return s.buf[:n]
}

func eof(err error) error {
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return io.EOF
	}
	return err
}

// readBlock reads one pcapng block, returning its type and body.
func (s *Reader) readBlock() (uint32, []byte, error) {
	var h [8]byte
	if _, err := io.ReadFull(s.r, h[:]); err != nil {
		return 0, nil, eof(err)
	}
	typ := s.bo.Uint32(h[:])
	total := s.bo.Uint32(h[4:])
	if total < 12 || total%4 != 0 || total > maxSnap+64 {
		return 0, nil, fmt.Errorf("capture: pcapng block of %d bytes", total)
	}
	body := s.grow(int(total) - 8)
	if _, err := io.ReadFull(s.r, body); err != nil {
		return 0, nil, eof(err)
	}
	return typ, body[:len(body)-4], nil // drop the trailing length
}

func (s *Reader) readSHB() error {
	var h [12]byte
	if _, err := io.ReadFull(s.r, h[:]); err != nil {
		return errFormat
	}
	switch binary.LittleEndian.Uint32(h[8:]) {
	case 0x1a2b3c4d:
		s.bo = binary.LittleEndian
	case 0x4d3c2b1a:
		s.bo = binary.BigEndian
	default:
		return errFormat
	}
	total := s.bo.Uint32(h[4:])
	if total < 28 || total%4 != 0 || total > maxSnap {
		return errFormat
	}
	if _, err := s.r.Discard(int(total) - 12); err != nil {
		return errFormat
	}
	s.ifaces = s.ifaces[:0] // a new section starts a new interface list
	return nil
}

func (s *Reader) readNG() ([]byte, time.Time, error) {
	for {
		if b, err := s.r.Peek(4); err == nil && b[0] == 0x0a && b[1] == 0x0d && b[2] == 0x0d && b[3] == 0x0a {
			if err := s.readSHB(); err != nil {
				return nil, time.Time{}, err
			}
			continue
		}
		typ, body, err := s.readBlock()
		if err != nil {
			return nil, time.Time{}, err
		}
		switch typ {
		case 1: // interface description
			if len(body) < 8 {
				return nil, time.Time{}, errFormat
			}
			ifc := ngIface{link: int(s.bo.Uint16(body)), unit: 1e-6}
			for opts := body[8:]; len(opts) >= 4; {
				code, l := s.bo.Uint16(opts), int(s.bo.Uint16(opts[2:]))
				if 4+l > len(opts) {
					break
				}
				if code == 9 && l >= 1 { // if_tsresol
					v := opts[4]
					if v&0x80 == 0 {
						ifc.unit = math.Pow(10, -float64(v))
					} else {
						ifc.unit = math.Pow(2, -float64(v&0x7f))
					}
				}
				if code == 0 {
					break
				}
				opts = opts[4+(l+3)/4*4:]
			}
			s.ifaces = append(s.ifaces, ifc)
		case 6: // enhanced packet
			if len(body) < 20 {
				return nil, time.Time{}, errFormat
			}
			id := int(s.bo.Uint32(body))
			if id >= len(s.ifaces) {
				return nil, time.Time{}, fmt.Errorf("capture: packet for undeclared interface %d", id)
			}
			ts := uint64(s.bo.Uint32(body[4:]))<<32 | uint64(s.bo.Uint32(body[8:]))
			capLen := int(s.bo.Uint32(body[12:]))
			if 20+capLen > len(body) {
				return nil, time.Time{}, errFormat
			}
			ifc := s.ifaces[id]
			s.link = ifc.link
			s.n++
			return body[20 : 20+capLen], tsTime(ts, ifc.unit), nil
		case 3: // simple packet: no timestamp
			if len(s.ifaces) == 0 || len(body) < 4 {
				return nil, time.Time{}, errFormat
			}
			s.link = s.ifaces[0].link
			s.n++
			return body[4:], time.Time{}, nil
		}
		// Other blocks (name resolution, statistics, custom) are skipped.
	}
}

func tsTime(ticks uint64, unit float64) time.Time {
	if unit == 1e-6 {
		return time.UnixMicro(int64(ticks)).UTC()
	}
	if unit == 1e-9 {
		return time.Unix(0, int64(ticks)).UTC()
	}
	sec := float64(ticks) * unit
	whole := math.Floor(sec)
	return time.Unix(int64(whole), int64((sec-whole)*1e9)).UTC()
}
