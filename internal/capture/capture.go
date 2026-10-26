// Package capture provides packet sources: live AF_PACKET capture on Linux
// (pure Go, TPACKET_V3 mmap ring) and pcap/pcapng files. Both hand the same
// raw frames to the sensor, so everything downstream is tested through
// files and deployed on interfaces.
package capture

import (
	"errors"
	"time"
)

// Link types (tcpdump.org/linktypes.html) the sensor parses.
const (
	LinkEthernet          = 1
	LinkRaw               = 101
	LinkIEEE80211         = 105
	LinkSLL               = 113
	LinkIEEE80211Radiotap = 127
	LinkIPv4              = 228
	LinkIPv6              = 229
	LinkSLL2              = 276
)

// IsWiFi reports a link type that carries 802.11 frames.
func IsWiFi(link int) bool {
	return link == LinkIEEE80211 || link == LinkIEEE80211Radiotap
}

// ErrTimeout is returned by ReadPacket when no packet arrived within the
// source's poll interval; the caller loops, checking for shutdown.
var ErrTimeout = errors.New("capture: timeout")

// Source yields captured frames. The returned data is valid until the next
// call to ReadPacket.
type Source interface {
	Name() string
	// LinkType is the link type of the frame last read (and of all frames,
	// for live capture and pcap files).
	LinkType() int
	ReadPacket() (data []byte, ts time.Time, err error)
	// Stats returns packets received and dropped by the kernel; files
	// report zero drops.
	Stats() (received, dropped uint64)
	Close() error
}
