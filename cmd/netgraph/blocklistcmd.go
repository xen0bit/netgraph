package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/xen0bit/netgraph/internal/model"
)

type blocklistBackend interface {
	Blocklists(context.Context) ([]model.Blocklist, error)
	Blocklist(context.Context, int64) (*model.Blocklist, error)
	SaveBlocklist(context.Context, *model.Blocklist) (*model.Blocklist, error)
	DeleteBlocklist(context.Context, int64) error
	BlocklistEntries(context.Context, int64, bool) ([]model.BlocklistEntry, error)
	ImportBlocklist(context.Context, int64, string, string) (*model.Blocklist, error)
	UpdateBlocklist(context.Context, int64, bool, bool) (*model.Blocklist, error)
	SetBlocklistEntry(context.Context, int64, int64, bool) error
	RuleGroups(context.Context) ([]model.RuleGroup, error)
	SaveRuleGroup(context.Context, *model.RuleGroup) (*model.RuleGroup, error)
}

func runBlocklist(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: netgraph blocklist list|show|add|import|update|delete|entries|enable|disable|groups")
	}
	switch args[0] {
	case "list":
		return runBlocklistList(args[1:])
	case "show":
		return runBlocklistShow(args[1:])
	case "add":
		return runBlocklistAdd(args[1:])
	case "import":
		return runBlocklistImport(args[1:])
	case "update":
		return runBlocklistUpdate(args[1:])
	case "delete":
		return runBlocklistDelete(args[1:])
	case "entries":
		return runBlocklistEntries(args[1:])
	case "enable", "disable":
		return runBlocklistEntrySet(args[1:], args[0] == "enable")
	case "groups":
		return runBlocklistGroups(args[1:])
	}
	return fmt.Errorf("blocklist: %q is not a command", args[0])
}

func openBlocklistBackend(b *backendFlags, write bool) (blocklistBackend, func(), error) {
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
	bb, ok := be.(blocklistBackend)
	if !ok {
		closeFn()
		return nil, nil, errors.New("this backend can't do blocklists")
	}
	return bb, closeFn, nil
}

func encode(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func runBlocklistList(args []string) error {
	fs := flag.NewFlagSet("blocklist list", flag.ContinueOnError)
	var b backendFlags
	b.register(fs)
	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	be, closeFn, err := openBlocklistBackend(&b, false)
	if err != nil {
		return err
	}
	defer closeFn()
	out, err := be.Blocklists(context.Background())
	if err != nil {
		return err
	}
	return encode(out)
}

func runBlocklistShow(args []string) error {
	fs := flag.NewFlagSet("blocklist show", flag.ContinueOnError)
	var b backendFlags
	b.register(fs)
	id := fs.Int64("id", 0, "blocklist ID")
	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *id == 0 && len(fs.Args()) > 0 {
		_, _ = fmt.Sscan(fs.Arg(0), id)
	}
	if *id == 0 {
		return errors.New("usage: netgraph blocklist show -id N")
	}
	be, closeFn, err := openBlocklistBackend(&b, false)
	if err != nil {
		return err
	}
	defer closeFn()
	out, err := be.Blocklist(context.Background(), *id)
	if err != nil {
		return err
	}
	return encode(out)
}

func runBlocklistAdd(args []string) error {
	fs := flag.NewFlagSet("blocklist add", flag.ContinueOnError)
	var b backendFlags
	b.register(fs)
	name := fs.String("name", "", "blocklist name")
	url := fs.String("url", "", "HTTPS source URL")
	format := fs.String("format", "auto", "auto, hosts, domains, ips or lsrules")
	group := fs.Int64("group", 0, "rule group ID")
	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *name == "" {
		return errors.New("usage: netgraph blocklist add -name NAME [-url URL] [-format auto]")
	}
	be, closeFn, err := openBlocklistBackend(&b, true)
	if err != nil {
		return err
	}
	defer closeFn()
	out, err := be.SaveBlocklist(context.Background(), &model.Blocklist{Name: *name, URL: *url, Format: *format, GroupID: *group, Enabled: true})
	if err != nil {
		return err
	}
	return encode(out)
}

func runBlocklistImport(args []string) error {
	fs := flag.NewFlagSet("blocklist import", flag.ContinueOnError)
	var b backendFlags
	b.register(fs)
	id := fs.Int64("id", 0, "blocklist ID")
	path := fs.String("file", "", "file to import; - reads stdin")
	format := fs.String("format", "auto", "auto, hosts, domains, ips or lsrules")
	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *id == 0 || *path == "" {
		return errors.New("usage: netgraph blocklist import -id N -file list.txt [-format auto]")
	}
	var raw []byte
	var err error
	if *path == "-" {
		raw, err = io.ReadAll(os.Stdin)
	} else {
		raw, err = os.ReadFile(*path)
	}
	if err != nil {
		return err
	}
	be, closeFn, err := openBlocklistBackend(&b, true)
	if err != nil {
		return err
	}
	defer closeFn()
	out, err := be.ImportBlocklist(context.Background(), *id, string(raw), *format)
	if err != nil {
		return err
	}
	return encode(out)
}

func runBlocklistUpdate(args []string) error {
	fs := flag.NewFlagSet("blocklist update", flag.ContinueOnError)
	var b backendFlags
	b.register(fs)
	id := fs.Int64("id", 0, "blocklist ID")
	allowPrivate := fs.Bool("allow-private", false, "allow a private address (local feed)")
	allowHTTP := fs.Bool("allow-http", false, "allow plain HTTP (local feed)")
	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *id == 0 {
		return errors.New("usage: netgraph blocklist update -id N")
	}
	be, closeFn, err := openBlocklistBackend(&b, true)
	if err != nil {
		return err
	}
	defer closeFn()
	out, err := be.UpdateBlocklist(context.Background(), *id, *allowPrivate, *allowHTTP)
	if err != nil {
		return err
	}
	return encode(out)
}

func runBlocklistDelete(args []string) error {
	fs := flag.NewFlagSet("blocklist delete", flag.ContinueOnError)
	var b backendFlags
	b.register(fs)
	id := fs.Int64("id", 0, "blocklist ID")
	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *id == 0 {
		return errors.New("usage: netgraph blocklist delete -id N")
	}
	be, closeFn, err := openBlocklistBackend(&b, true)
	if err != nil {
		return err
	}
	defer closeFn()
	return be.DeleteBlocklist(context.Background(), *id)
}

func runBlocklistEntries(args []string) error {
	fs := flag.NewFlagSet("blocklist entries", flag.ContinueOnError)
	var b backendFlags
	b.register(fs)
	id := fs.Int64("id", 0, "blocklist ID")
	enabled := fs.Bool("enabled", false, "only enabled entries")
	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *id == 0 {
		return errors.New("usage: netgraph blocklist entries -id N")
	}
	be, closeFn, err := openBlocklistBackend(&b, false)
	if err != nil {
		return err
	}
	defer closeFn()
	out, err := be.BlocklistEntries(context.Background(), *id, *enabled)
	if err != nil {
		return err
	}
	return encode(out)
}

func runBlocklistEntrySet(args []string, enabled bool) error {
	fs := flag.NewFlagSet("blocklist entry", flag.ContinueOnError)
	var b backendFlags
	b.register(fs)
	id := fs.Int64("id", 0, "blocklist ID")
	entry := fs.Int64("entry", 0, "entry ID")
	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *id == 0 || *entry == 0 {
		return errors.New("usage: netgraph blocklist enable|disable -id N -entry N")
	}
	be, closeFn, err := openBlocklistBackend(&b, true)
	if err != nil {
		return err
	}
	defer closeFn()
	return be.SetBlocklistEntry(context.Background(), *id, *entry, enabled)
}

func runBlocklistGroups(args []string) error {
	fs := flag.NewFlagSet("blocklist groups", flag.ContinueOnError)
	var b backendFlags
	b.register(fs)
	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	be, closeFn, err := openBlocklistBackend(&b, false)
	if err != nil {
		return err
	}
	defer closeFn()
	out, err := be.RuleGroups(context.Background())
	if err != nil {
		return err
	}
	return encode(out)
}
