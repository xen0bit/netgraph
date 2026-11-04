//go:build linux

package conntrack

import (
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"
)

const (
	netlinkNetfilter = 12
	msgCTGet         = 1<<8 | 1 // NFNL_SUBSYS_CTNETLINK, IPCTNL_MSG_CT_GET
	flagRequest      = 0x1
	flagDump         = 0x100 | 0x200 // NLM_F_ROOT | NLM_F_MATCH
	nfnetlinkV0      = 0
	maxDumpBytes     = 256 << 20 // well past MaxEntries at a few hundred bytes each
)

// Dump reads the whole table over netlink. It needs CAP_NET_ADMIN. complete is false if
// the table was bigger than MaxEntries or the kernel dropped part of the answer.
func Dump() ([]Entry, bool, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, netlinkNetfilter)
	if err != nil {
		return nil, false, fmt.Errorf("conntrack: netlink: %w", err)
	}
	defer func() { _ = syscall.Close(fd) }()
	tv := syscall.Timeval{Sec: 5}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return nil, false, fmt.Errorf("conntrack: netlink: %w", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, false, fmt.Errorf("conntrack: netlink: %w", err)
	}
	req := make([]byte, nlmsgHeader+nfgenHeader)
	order := binary.NativeEndian
	order.PutUint32(req, uint32(len(req)))
	order.PutUint16(req[4:], msgCTGet)
	order.PutUint16(req[6:], flagRequest|flagDump)
	order.PutUint32(req[8:], 1) // sequence
	// family 0 is both IPv4 and IPv6.
	req[nlmsgHeader+1] = nfnetlinkV0
	if err := syscall.Sendto(fd, req, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, false, permissionHint(fmt.Errorf("conntrack: netlink: %w", err))
	}
	buf := make([]byte, 64<<10)
	var entries []Entry
	total := 0
	for total < maxDumpBytes {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if errors.Is(err, syscall.ENOBUFS) {
			return entries, false, nil // the kernel lost part of it; what arrived is still true
		}
		if err != nil {
			return nil, false, permissionHint(fmt.Errorf("conntrack: netlink: %w", err))
		}
		if n == 0 {
			return entries, false, nil
		}
		total += n
		var done bool
		entries, done, err = Parse(buf[:n], order, entries)
		if err != nil {
			return nil, false, kernelError(buf[:n], order)
		}
		if done {
			return entries, len(entries) < MaxEntries, nil
		}
	}
	return entries, false, nil
}

// kernelError finds the errno in a netlink error message, which Parse has already seen.
func kernelError(b []byte, order binary.ByteOrder) error {
	for len(b) >= nlmsgHeader+4 {
		n := int(order.Uint32(b))
		if n < nlmsgHeader || n > len(b) {
			break
		}
		if order.Uint16(b[4:]) == nlmsgError {
			return permissionHint(fmt.Errorf("conntrack: netlink: %w", syscall.Errno(-int32(order.Uint32(b[nlmsgHeader:])))))
		}
		b = b[(n+3)&^3:]
	}
	return ErrKernel
}

func permissionHint(err error) error {
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		return fmt.Errorf("%w (reading conntrack needs CAP_NET_ADMIN)", err)
	}
	return err
}
