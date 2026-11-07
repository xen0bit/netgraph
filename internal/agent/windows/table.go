// Package windows implements the Windows host-agent scanner: TCP sockets
// with their owning processes from iphlpapi's GetExtendedTcpTable, and each
// process's image from the process list. It needs no cgo.
//
// The table layouts are parsed here, in a file with no build tag, so they are
// tested on every platform; the system calls are in scan_windows.go.
package windows

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strconv"

	"github.com/xen0bit/netgraph/internal/agent"
)

// Row sizes of MIB_TCPROW_OWNER_PID and MIB_TCP6ROW_OWNER_PID.
const (
	row4Size = 24 // state, local addr, local port, remote addr, remote port, pid
	row6Size = 56 // local addr[16], scope, port, remote addr[16], scope, port, state, pid
)

var errShort = errors.New("tcp table: short buffer")

// ParseTCP4 reads a MIB_TCPTABLE_OWNER_PID: a count, then rows. Addresses
// are in network order, ports in network order in a DWORD's low 16 bits.
func ParseTCP4(b []byte) ([]agent.Socket, error) {
	n, rows, err := table(b, row4Size)
	if err != nil {
		return nil, err
	}
	out := make([]agent.Socket, 0, n)
	for i := 0; i < n; i++ {
		r := rows[i*row4Size : (i+1)*row4Size]
		le := binary.LittleEndian
		out = append(out, socket(le.Uint32(r[0:]), netip.AddrFrom4([4]byte(r[4:8])), port(r[8:]),
			netip.AddrFrom4([4]byte(r[12:16])), port(r[16:]), le.Uint32(r[20:])))
	}
	return out, nil
}

// ParseTCP6 reads a MIB_TCP6TABLE_OWNER_PID.
func ParseTCP6(b []byte) ([]agent.Socket, error) {
	n, rows, err := table(b, row6Size)
	if err != nil {
		return nil, err
	}
	out := make([]agent.Socket, 0, n)
	for i := 0; i < n; i++ {
		r := rows[i*row6Size : (i+1)*row6Size]
		le := binary.LittleEndian
		out = append(out, socket(le.Uint32(r[48:]), netip.AddrFrom16([16]byte(r[0:16])), port(r[20:]),
			netip.AddrFrom16([16]byte(r[24:40])), port(r[44:]), le.Uint32(r[52:])))
	}
	return out, nil
}

// table checks a table's count against its buffer, and bounds it.
func table(b []byte, rowSize int) (int, []byte, error) {
	if len(b) < 4 {
		return 0, nil, errShort
	}
	n := int(binary.LittleEndian.Uint32(b))
	rows := b[4:]
	if n < 0 || n > len(rows)/rowSize {
		return 0, nil, errShort
	}
	return min(n, agent.MaxConnections*4), rows, nil
}

func port(b []byte) int { return int(b[0])<<8 | int(b[1]) }

func socket(state uint32, local netip.Addr, lport int, remote netip.Addr, rport int, pid uint32) agent.Socket {
	return agent.Socket{
		Proto: "tcp", LocalIP: local.String(), LocalPort: lport, RemoteIP: remote.String(), RemotePort: rport,
		State: stateName(state), PID: int(pid),
		// No inode here: a port reused by another process is still a new
		// connection.
		ID: "pid" + strconv.FormatUint(uint64(pid), 10),
	}
}

// stateName names a MIB_TCP_STATE as Linux names TCP states.
func stateName(s uint32) string {
	names := [...]string{1: "CLOSE", 2: "LISTEN", 3: "SYN_SENT", 4: "SYN_RECV", 5: "ESTABLISHED", 6: "FIN_WAIT1",
		7: "FIN_WAIT2", 8: "CLOSE_WAIT", 9: "CLOSING", 10: "LAST_ACK", 11: "TIME_WAIT", 12: "DELETE_TCB"}
	if int(s) < len(names) && names[s] != "" {
		return names[s]
	}
	return strconv.FormatUint(uint64(s), 10)
}

// Connections turns sockets into connections, using procs for each owning
// process; listeners decide which were accepted.
func Connections(sockets []agent.Socket, procs map[int]agent.Process, now int64) []agent.Connection {
	listening := map[agent.Listener]bool{}
	for _, s := range sockets {
		if s.State == "LISTEN" {
			listening[agent.Listener{Proto: s.Proto, Port: s.LocalPort}] = true
		}
	}
	var out []agent.Connection
	for _, s := range sockets {
		if !s.Connected() || s.State == "LISTEN" {
			continue
		}
		out = append(out, agent.NewConnection(s, listening, procs[s.PID], now))
		if len(out) >= agent.MaxConnections {
			break
		}
	}
	return out
}
