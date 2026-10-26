//go:build linux

package capture

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gopacket/gopacket/afpacket"
)

// LiveConfig configures live capture.
type LiveConfig struct {
	Interface   string
	RingBytes   int  // mmap ring size; default 8 MiB
	Promiscuous bool // for SPAN/mirror ports; a router sees its own traffic without it
}

// OpenLive opens an AF_PACKET TPACKET_V3 socket on an interface.
func OpenLive(cfg LiveConfig) (Source, error) {
	iface, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		return nil, err
	}
	if cfg.RingBytes <= 0 {
		cfg.RingBytes = 8 << 20
	}
	const frame = 1 << 16 // snap length: a whole GRO'd superpacket's headers and opening bytes
	const block = 1 << 20
	blocks := max(cfg.RingBytes/block, 2)
	h, err := afpacket.NewTPacket(
		afpacket.OptInterface(cfg.Interface),
		afpacket.OptFrameSize(frame),
		afpacket.OptBlockSize(block),
		afpacket.OptNumBlocks(blocks),
		afpacket.OptPollTimeout(250*time.Millisecond),
		afpacket.OptBlockTimeout(50*time.Millisecond),
		afpacket.TPacketVersion3,
	)
	if err != nil {
		return nil, fmt.Errorf("af_packet on %s: %w (needs CAP_NET_RAW)", cfg.Interface, err)
	}
	if cfg.Promiscuous {
		if err := h.SetPromiscuous(true); err != nil {
			h.Close()
			return nil, fmt.Errorf("promiscuous mode on %s: %w", cfg.Interface, err)
		}
	}
	_ = h.InitSocketStats()
	return &liveSource{name: cfg.Interface, h: h, link: linkTypeFor(iface)}, nil
}

// linkTypeFor reads the kernel's ARPHRD type for the interface. Monitor
// interfaces have no special hardware address, so the Ethernet guess alone
// would decode their radiotap frames as Ethernet.
func linkTypeFor(iface *net.Interface) int {
	switch arphrd(iface.Name) {
	case 801: // ARPHRD_IEEE80211
		return LinkIEEE80211
	case 803: // ARPHRD_IEEE80211_RADIOTAP
		return LinkIEEE80211Radiotap
	}
	if len(iface.HardwareAddr) == 0 {
		return LinkRaw // tun/wireguard/ppp: frames are bare IP packets
	}
	return LinkEthernet
}

func arphrd(name string) int {
	b, err := os.ReadFile("/sys/class/net/" + name + "/type")
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}

type liveSource struct {
	name string
	h    *afpacket.TPacket
	link int
}

func (s *liveSource) Name() string  { return s.name }
func (s *liveSource) LinkType() int { return s.link }
func (s *liveSource) Close() error  { s.h.Close(); return nil }

func (s *liveSource) ReadPacket() ([]byte, time.Time, error) {
	data, ci, err := s.h.ZeroCopyReadPacketData()
	if err != nil {
		if errors.Is(err, afpacket.ErrTimeout) || errors.Is(err, afpacket.ErrPoll) {
			return nil, time.Time{}, ErrTimeout
		}
		return nil, time.Time{}, err
	}
	return data, ci.Timestamp, nil
}

func (s *liveSource) Stats() (uint64, uint64) {
	_, v3, err := s.h.SocketStats()
	if err != nil {
		return 0, 0
	}
	// SocketStats are cumulative since InitSocketStats in this library.
	return uint64(v3.Packets()), uint64(v3.Drops())
}
