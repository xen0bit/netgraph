package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/xen0bit/netgraph/internal/model"
)

type askBackend interface {
	Ask(context.Context, string, model.Filter) (*model.Answer, error)
}

func runAsk(args []string) error {
	fs := flag.NewFlagSet("ask", flag.ContinueOnError)
	var b backendFlags
	var f filterFlags
	b.register(fs)
	f.register(fs)
	out := fs.String("o", "table", "output: table or json")
	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	q := strings.TrimSpace(strings.Join(fs.Args(), " "))
	if q == "" {
		return errors.New("usage: netgraph ask \"what did the printer do yesterday?\"")
	}
	filter, err := f.filter()
	if err != nil {
		return err
	}
	be, closeFn, err := b.open()
	if err != nil {
		return err
	}
	defer closeFn()
	ab, ok := be.(askBackend)
	if !ok {
		return errors.New("this backend does not support ask")
	}
	a, err := ab.Ask(context.Background(), q, filter)
	if err != nil {
		return err
	}
	if *out == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(a)
	}
	if *out != "table" {
		return fmt.Errorf("-o: %q is not table or json", *out)
	}
	fmt.Println(a.Answer)
	for _, c := range a.Claims {
		fmt.Printf("  - %s", c.Text)
		if len(c.Evidence) > 0 {
			var refs []string
			for _, e := range c.Evidence {
				refs = append(refs, e.Kind+":"+e.ID)
			}
			fmt.Printf("  [%s]", strings.Join(refs, ", "))
		}
		fmt.Println()
	}
	for _, g := range a.Gaps {
		fmt.Fprintf(os.Stderr, "gap: %s\n", g)
	}
	return nil
}
