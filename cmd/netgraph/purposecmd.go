package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/purpose"
)

type purposeBackend interface {
	Purposes(context.Context, string) ([]model.Purpose, error)
	ImportPurpose(context.Context, *purpose.Manifest) (int, error)
	DeletePurpose(context.Context, int64) error
}

func runPurpose(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: netgraph purpose list|lookup|import|delete")
	}
	switch args[0] {
	case "list", "lookup":
		return runPurposeList(args[1:], args[0] == "lookup")
	case "import":
		return runPurposeImport(args[1:])
	case "delete":
		return runPurposeDelete(args[1:])
	}
	return fmt.Errorf("purpose: %q is not a command", args[0])
}

func openPurposeBackend(b *backendFlags, write bool) (purposeBackend, func(), error) {
	var be model.Backend
	var closeFn func()
	var err error
	if write {
		be, closeFn, err = b.openWritable()
	} else {
		be, closeFn, err = b.open()
	}
	if err != nil {
		return nil, nil, err
	}
	pb, ok := be.(purposeBackend)
	if !ok {
		closeFn()
		return nil, nil, errors.New("this backend can't do purposes")
	}
	return pb, closeFn, nil
}

func runPurposeList(args []string, lookup bool) error {
	fs := flag.NewFlagSet("purpose", flag.ContinueOnError)
	var b backendFlags
	b.register(fs)
	host := fs.String("host", "", "host name")
	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *host == "" && len(fs.Args()) > 0 {
		*host = strings.TrimSpace(fs.Arg(0))
	}
	be, closeFn, err := openPurposeBackend(&b, false)
	if err != nil {
		return err
	}
	defer closeFn()
	out, err := be.Purposes(context.Background(), *host)
	if err != nil {
		return err
	}
	return encode(out)
}

func runPurposeImport(args []string) error {
	fs := flag.NewFlagSet("purpose import", flag.ContinueOnError)
	var b backendFlags
	b.register(fs)
	path := fs.String("file", "", "manifest JSON; - reads stdin")
	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *path == "" && len(fs.Args()) > 0 {
		*path = fs.Arg(0)
	}
	if *path == "" {
		return errors.New("usage: netgraph purpose import -file manifest.json")
	}
	var r *os.File
	var err error
	if *path == "-" {
		r = os.Stdin
	} else {
		r, err = os.Open(*path)
		if err != nil {
			return err
		}
		defer r.Close()
	}
	m, err := purpose.Parse(r)
	if err != nil {
		return err
	}
	be, closeFn, err := openPurposeBackend(&b, true)
	if err != nil {
		return err
	}
	defer closeFn()
	n, err := be.ImportPurpose(context.Background(), m)
	if err != nil {
		return err
	}
	return encode(map[string]any{"application": m.Application, "imported": n})
}

func runPurposeDelete(args []string) error {
	fs := flag.NewFlagSet("purpose delete", flag.ContinueOnError)
	var b backendFlags
	b.register(fs)
	id := fs.Int64("id", 0, "purpose ID")
	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	be, closeFn, err := openPurposeBackend(&b, true)
	if err != nil {
		return err
	}
	defer closeFn()
	return be.DeletePurpose(context.Background(), *id)
}
