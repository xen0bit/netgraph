// Command netgraph-sensor runs on the router. It captures LAN traffic, decodes
// it into events (flows, DNS, DHCP, mDNS, ARP/NDP, TLS SNI, ...) and ships them
// to a netgraph server. It keeps no database: everything it learns leaves the
// box, so it fits a 512 MB router and cross-compiles to every Linux arch,
// mips included.
//
//	netgraph-sensor run -iface br-lan -server https://host:8443 -token-file F
//	netgraph-sensor run -pcap capture.pcap -server ...
//	netgraph-sensor version
//
// Capturing needs CAP_NET_RAW: run as root, or `setcap cap_net_raw+ep`.
//
// This binary must never link SQLite or d2 — they do not build for mips, and
// the size budget is a few MB. deps_test.go enforces it.
package main

import (
	"fmt"
	"os"

	"github.com/xen0bit/netgraph/internal/buildinfo"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version", "-version", "--version":
		fmt.Println(buildinfo.String("netgraph-sensor"))
	case "help", "-h", "-help", "--help":
		usage()
	case "run":
		fmt.Fprintln(os.Stderr, "netgraph-sensor: run is not implemented yet")
		os.Exit(1)
	default:
		fmt.Fprintf(os.Stderr, "netgraph-sensor: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: netgraph-sensor <command> [flags]

commands:
  run        capture and ship events to a netgraph server
  version    print version information
`)
}
