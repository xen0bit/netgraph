// Command netgraph is the persistence host: it ingests sensor events into
// SQLite, correlates them into a graph of devices, addresses, names and
// services over time, and serves queries, graphs, a TUI and the web UI.
//
//	netgraph serve  -db netgraph.db -listen :8443
//	netgraph query  devices|flows|dns|facts|... -from -24h [filters]
//	netgraph graph  -from ... -to ... -o out.svg|.d2|.txt
//	netgraph tui
//	netgraph import capture.pcap
//	netgraph db     migrate|backup|retain|vacuum
//	netgraph version
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/xen0bit/netgraph/internal/buildinfo"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "version", "-version", "--version":
		fmt.Println(buildinfo.String("netgraph"))
	case "help", "-h", "-help", "--help":
		usage()
	case "serve":
		err = runServe(os.Args[2:])
	case "query", "q":
		err = runQuery(os.Args[2:])
	case "graph":
		err = runGraph(os.Args[2:])
	case "tui":
		err = runTUI(os.Args[2:])
	case "import":
		err = runImport(os.Args[2:])
	case "db":
		err = runDB(os.Args[2:])
	case "label":
		err = runLabel(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "netgraph: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if errors.Is(err, flag.ErrHelp) {
		os.Exit(0)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "netgraph:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: netgraph <command> [flags]

commands:
  serve      ingest sensor events and serve the API and web UI
  query      print summary, devices, flows, dns, facts, timeseries, an entity, sensors
  graph      render the graph for a time window (.svg, .d2, .txt, .json)
  tui        interactive terminal UI
  label      name a device by hand (or -clear the name)
  import     ingest pcap/pcapng files directly
  db         database maintenance (migrate, backup, retain, vacuum)
  version    print version information

Queries go to -server URL ($NETGRAPH_SERVER) when set, else read the
database file -db ($NETGRAPH_DB, default netgraph.db).
Run 'netgraph <command> -h' for a command's flags.
`)
}
