//go:build linux

package wifi

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// SetChannel changes a monitor interface's channel through the wireless
// extensions ioctl (SIOCSIWFREQ). It is the one ioctl every mac80211 monitor
// interface understands; nl80211 would be larger and is not needed for a
// fixed channel list.
//
// The interface must already be in monitor mode:
//
//	iw dev wlan0 interface add mon0 type monitor
//	ip link set mon0 up
func SetChannel(iface string, channel int) error {
	if channel <= 0 {
		return fmt.Errorf("wifi: channel %d", channel)
	}
	if len(iface) == 0 || len(iface) > 15 {
		return fmt.Errorf("wifi: interface name %q", iface)
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()

	// struct iwreq: 16-byte name, then struct iw_freq (s32 m, s16 e,
	// u8 i, u8 flags) in a 16-byte union.
	var req [32]byte
	copy(req[:16], iface)
	binary.NativeEndian.PutUint32(req[16:], uint32(channel))
	binary.NativeEndian.PutUint16(req[20:], 0) // exponent
	req[22] = 0                                // list index
	req[23] = 0x01                             // IW_FREQ_FIXED

	const siocsiwfreq = 0x8b04
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), siocsiwfreq, uintptr(unsafe.Pointer(&req[0]))); errno != 0 {
		return fmt.Errorf("wifi: set %s to channel %d: %w", iface, channel, errno)
	}
	return nil
}
