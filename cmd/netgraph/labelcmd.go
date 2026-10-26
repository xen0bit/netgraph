package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/xen0bit/netgraph/internal/apiclient"
	"github.com/xen0bit/netgraph/internal/store"
)

func runLabel(args []string) error {
	fs := flag.NewFlagSet("label", flag.ContinueOnError)
	var b backendFlags
	b.register(fs)
	clearLabel := fs.Bool("clear", false, "remove the name, restoring the automatic one")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `usage: netgraph label [flags] MAC NAME...
       netgraph label [flags] -clear MAC

Names a device by hand. The name overrides DHCP, mDNS and every other
automatic source until it is cleared. Without -server, the database file is
written directly: stop the server first, or it may not see the change.

`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 || *clearLabel != (fs.NArg() == 1) {
		fs.Usage()
		return errors.New("give a MAC and a name, or -clear and a MAC")
	}
	mac, name := fs.Arg(0), strings.Join(fs.Args()[1:], " ")
	ctx := context.Background()
	if b.server != "" {
		tok, err := readSecret(b.tokenFile, "NETGRAPH_READ_TOKEN")
		if err != nil {
			return err
		}
		return apiclient.NewClient(b.server, tok).SetDeviceLabel(ctx, mac, name)
	}
	st, err := store.Open(b.db, store.Config{Logger: quietLogger()})
	if err != nil {
		return err
	}
	defer st.Close()
	return st.SetDeviceLabel(ctx, mac, name)
}
