// Package capture provides packet sources: live AF_PACKET capture on Linux
// (pure Go, TPACKET_V3 mmap ring) and pcap/pcapng files. Both hand the same
// raw frames to the sensor, so everything downstream is tested through
// files and deployed on interfaces.
package capture

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// LinkType values the sensor parses.
const (
	LinkEthernet = int(layers.LinkTypeEthernet)
	LinkRaw      = int(layers.LinkTypeRaw)
	LinkIPv4     = int(layers.LinkTypeIPv4)
	LinkIPv6     = int(layers.LinkTypeIPv6)
	LinkSLL      = int(layers.LinkTypeLinuxSLL)
	LinkSLL2     = 276
)

// ErrTimeout is returned by ReadPacket when no packet arrived within the
// source's poll interval; the caller loops, checking for shutdown.
var ErrTimeout = errors.New("capture: timeout")

// Source yields captured frames. The returned data is valid until the next
// call to ReadPacket.
type Source interface {
	Name() string
	LinkType() int
	ReadPacket() (data []byte, ts time.Time, err error)
	// Stats returns packets received and dropped by the kernel; files
	// report zero drops.
	Stats() (received, dropped uint64)
	Close() error
}

// OpenFile opens a pcap or pcapng file.
func OpenFile(path string) (Source, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	br := bufio.NewReaderSize(f, 1<<20)
	magic, err := br.Peek(4)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	s := &fileSource{name: path, f: f}
	if magic[0] == 0x0a && magic[1] == 0x0d && magic[2] == 0x0d && magic[3] == 0x0a {
		ng, err := pcapgo.NewNgReader(br, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		s.r, s.link = ng, int(ng.LinkType())
	} else {
		r, err := pcapgo.NewReader(br)
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		s.r, s.link = r, int(r.LinkType())
	}
	return s, nil
}

type fileSource struct {
	name string
	f    *os.File
	r    interface {
		ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	}
	link int
	n    uint64
}

func (s *fileSource) Name() string  { return s.name }
func (s *fileSource) LinkType() int { return s.link }
func (s *fileSource) Close() error  { return s.f.Close() }
func (s *fileSource) Stats() (uint64, uint64) {
	return s.n, 0
}

func (s *fileSource) ReadPacket() ([]byte, time.Time, error) {
	data, ci, err := s.r.ReadPacketData()
	if err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			err = io.EOF // a capture cut off mid-packet still ends cleanly
		}
		return nil, time.Time{}, err
	}
	s.n++
	return data, ci.Timestamp, nil
}
