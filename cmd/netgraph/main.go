// Command netgraph is the persistence host: it ingests sensor events into
// SQLite, correlates them into a graph of devices, addresses, names and
// services over time, and serves queries, graphs, a TUI and the web UI.
//
//	netgraph serve  -db netgraph.db -listen :8443
//	netgraph query  devices|flows|dns|edges -from -24h [filters]
//	netgraph graph  -from ... -to ... -o out.svg|.d2|.txt
//	netgraph tui
//	netgraph import capture.pcap
//	netgraph db     backup|vacuum|migrate
//	netgraph version
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
		fmt.Println(buildinfo.String("netgraph"))
	case "help", "-h", "-help", "--help":
		usage()
	case "serve", "query", "graph", "tui", "import", "db":
		fmt.Fprintf(os.Stderr, "netgraph: %s is not implemented yet\n", os.Args[1])
		os.Exit(1)
	default:
		fmt.Fprintf(os.Stderr, "netgraph: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: netgraph <command> [flags]

commands:
  serve      ingest sensor events and serve the API and web UI
  query      print devices, flows, dns or edges for a time window
  graph      render the graph for a time window (.svg, .d2, .txt)
  tui        interactive terminal UI
  import     ingest a pcap file directly
  db         database maintenance (backup, vacuum, migrate)
  version    print version information
`)
}
