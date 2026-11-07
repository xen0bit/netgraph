//go:build windows

package windows

import (
	"context"
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/xen0bit/netgraph/internal/agent"
)

const (
	afInet              = 2
	afInet6             = 23
	tcpTableOwnerPIDAll = 5
	errInsufficient     = 122 // ERROR_INSUFFICIENT_BUFFER
)

var procGetExtendedTCPTable = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetExtendedTcpTable")

// Scanner reads the TCP tables and the process list. UDP has no peer in
// these tables, so only TCP is reported.
type Scanner struct {
	// Cmdlines is accepted for symmetry with Linux; Windows reports only
	// the image, never arguments.
	Cmdlines bool
	hash     agent.Hasher
}

// Capabilities says what this scanner reports.
func (s *Scanner) Capabilities() []string { return []string{"process-identity", "tcp-table"} }

// Scan returns the current process and connection snapshot.
func (s *Scanner) Scan(ctx context.Context) ([]agent.Process, []agent.Connection, error) {
	var sockets []agent.Socket
	for _, t := range []struct {
		af    uint32
		parse func([]byte) ([]agent.Socket, error)
	}{{afInet, ParseTCP4}, {afInet6, ParseTCP6}} {
		b, err := tcpTable(t.af)
		if err != nil {
			return nil, nil, err
		}
		so, err := t.parse(b)
		if err != nil {
			return nil, nil, err
		}
		sockets = append(sockets, so...)
	}
	if ctx.Err() != nil {
		return nil, nil, ctx.Err()
	}
	pids := map[int]bool{}
	for _, so := range sockets {
		if so.Connected() && so.PID > 0 {
			pids[so.PID] = true
		}
	}
	all := processList()
	procs := map[int]agent.Process{}
	var list []agent.Process
	for pid := range pids {
		p, ok := all[pid]
		if !ok {
			p = agent.Process{PID: pid}
		}
		p.Path, p.Start = image(uint32(pid))
		if p.Path == "" {
			p.Path = p.Cmdline // the image name from the process list
		}
		p.Cmdline = agent.ClipCmdline(p.Cmdline, false)
		p.SHA256, p.CodeID = s.hash.Hash(p.Path, p.Path)
		procs[pid] = p
		if len(list) < agent.MaxProcesses {
			list = append(list, p)
		}
	}
	return list, Connections(sockets, procs, time.Now().UnixMilli()), nil
}

// tcpTable fetches one address family's table, growing the buffer as asked.
func tcpTable(af uint32) ([]byte, error) {
	size := uint32(64 << 10)
	for range 8 {
		buf := make([]byte, size)
		r, _, _ := procGetExtendedTCPTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0,
			uintptr(af), tcpTableOwnerPIDAll, 0)
		switch r {
		case 0:
			return buf, nil
		case errInsufficient:
			size += 16 << 10 // the table can grow between calls
			if size > 64<<20 {
				return nil, fmt.Errorf("GetExtendedTcpTable: table too large")
			}
		default:
			return nil, fmt.Errorf("GetExtendedTcpTable: %w", windows.Errno(r))
		}
	}
	return nil, fmt.Errorf("GetExtendedTcpTable: table keeps growing")
}

// processList maps PIDs to their parent and image name.
func processList() map[int]agent.Process {
	out := map[int]agent.Process{}
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return out
	}
	defer func() { _ = windows.CloseHandle(snap) }()
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	for err := windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		out[int(e.ProcessID)] = agent.Process{PID: int(e.ProcessID), PPID: int(e.ParentProcessID), Cmdline: windows.UTF16ToString(e.ExeFile[:])}
		if len(out) > 100000 {
			break
		}
	}
	return out
}

// image is a process's full image path and start time, when this agent may
// query it (an elevated agent can query almost every process).
func image(pid uint32) (string, int64) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", 0
	}
	defer func() { _ = windows.CloseHandle(h) }()
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	path := ""
	if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) == nil {
		path = windows.UTF16ToString(buf[:n])
	}
	var created, exited, kernel, user windows.Filetime
	var start int64
	if windows.GetProcessTimes(h, &created, &exited, &kernel, &user) == nil {
		start = created.Nanoseconds() / int64(time.Millisecond)
	}
	return path, start
}
