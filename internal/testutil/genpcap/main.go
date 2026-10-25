// Command genpcap writes the testutil home-network scenario as a pcap file:
// a capture with DHCP, ARP, NDP, mDNS, SSDP, NBNS, LLMNR, LLDP, DNS, TLS,
// QUIC and HTTP whose every packet is known. It is the demo data for
// `make demo` and the docs.
//
//	go run ./internal/testutil/genpcap [-at 2026-10-25T12:00:00Z] out.pcap
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/xen0bit/netgraph/internal/testutil"
)

type tb struct{ dir string }

func (tb) Helper()                      {}
func (tb) Fatal(args ...any)            { fmt.Fprintln(os.Stderr, args...); os.Exit(1) }
func (tb) Fatalf(f string, args ...any) { fmt.Fprintf(os.Stderr, f+"\n", args...); os.Exit(1) }
func (t tb) TempDir() string            { return t.dir }

func main() {
	at := flag.String("at", "", "scenario start time (RFC 3339); default: 10 minutes ago")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: genpcap [-at time] out.pcap")
		os.Exit(2)
	}
	start := time.Now().Add(-10 * time.Minute).Truncate(time.Second)
	if *at != "" {
		t, err := time.Parse(time.RFC3339, *at)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		start = t
	}
	testutil.Base = start
	dir, err := os.MkdirTemp("", "genpcap")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer os.RemoveAll(dir)
	path := testutil.Home(tb{dir}).WriteFile()
	in, err := os.Open(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer in.Close()
	out, err := os.Create(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if _, err := io.Copy(out, in); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := out.Close(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "wrote %s (scenario starts %s)\n", flag.Arg(0), start.Format(time.RFC3339))
}
