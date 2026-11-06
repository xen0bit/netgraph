package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/xen0bit/netgraph/internal/backup"
	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/policy"
)

type policyBackend interface {
	LearnPolicy(context.Context, string, model.Filter) (*policy.Learned, error)
	ExportPolicy(context.Context, *policy.Policy, string, model.Filter) (*policy.Exported, error)
	Policies(context.Context) ([]policy.Summary, error)
	Policy(context.Context, string) (*policy.Policy, error)
	ActivePolicy(context.Context) (*policy.Policy, error)
	SavePolicy(context.Context, *policy.Policy) (*policy.Policy, error)
	DeletePolicy(context.Context, string) error
	ActivatePolicy(context.Context, string) error
	AuditPolicy(context.Context, *policy.Policy) (*policy.AuditReport, error)
	ExportBundle(context.Context) (*backup.Bundle, error)
	ImportBundle(context.Context, *backup.Bundle) (map[string]int, error)
}

func runPolicy(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: netgraph policy list|show|create|edit|delete|activate|learn|export|explain")
	}
	switch args[0] {
	case "list":
		return runPolicyList(args[1:])
	case "show":
		return runPolicyShow(args[1:])
	case "create":
		return runPolicySave(args[1:], false)
	case "edit":
		return runPolicySave(args[1:], true)
	case "delete":
		return runPolicyDelete(args[1:])
	case "activate":
		return runPolicyActivate(args[1:])
	case "explain":
		return runPolicyExplain(args[1:])
	case "audit":
		return runPolicyAudit(args[1:])
	case "backup":
		return runPolicyBackup(args[1:])
	case "restore":
		return runPolicyRestore(args[1:])
	case "verify":
		return runPolicyVerify(args[1:])
	case "learn":
		return runPolicyLearn(args[1:])
	case "export":
		return runPolicyExport(args[1:])
	}
	return fmt.Errorf("policy: %q is not list, show, create, edit, delete, activate, learn, export or explain", args[0])
}

func openPolicyBackend(b *backendFlags) (policyBackend, func(), error) {
	return openPolicyBackendFor(b, false)
}

func openPolicyBackendFor(b *backendFlags, write bool) (policyBackend, func(), error) {
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
	pb, ok := be.(policyBackend)
	if !ok {
		closeFn()
		return nil, nil, errors.New("this backend can't do policies")
	}
	return pb, closeFn, nil
}

func runPolicyLearn(args []string) error {
	fs := flag.NewFlagSet("policy learn", flag.ContinueOnError)
	var b backendFlags
	var f filterFlags
	b.register(fs)
	f.register(fs)
	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if f.device == "" {
		return errors.New("usage: netgraph policy learn -device MAC [-from -14d] > policy.json")
	}
	defaultTwoWeeks(&f, fs)
	filter, err := f.filter()
	if err != nil {
		return err
	}
	be, closeFn, err := openPolicyBackend(&b)
	if err != nil {
		return err
	}
	defer closeFn()
	got, err := be.LearnPolicy(context.Background(), f.device, filter)
	if err != nil {
		return err
	}
	for _, g := range got.Gaps {
		fmt.Fprintln(os.Stderr, "note:", g)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(got.Policy)
}

func runPolicyExport(args []string) error {
	fs := flag.NewFlagSet("policy export", flag.ContinueOnError)
	var b backendFlags
	var f filterFlags
	b.register(fs)
	f.register(fs)
	path := fs.String("policy", "", "policy JSON file")
	format := fs.String("format", policy.FormatNftables, "nftables, openwrt or opnsense")
	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *path == "" {
		return errors.New("usage: netgraph policy export -policy policy.json -format nftables [-from -14d]")
	}
	raw, err := os.ReadFile(*path)
	if err != nil {
		return err
	}
	p, err := policy.Parse(strings.NewReader(string(raw)))
	if err != nil {
		return err
	}
	defaultTwoWeeks(&f, fs)
	filter, err := f.filter()
	if err != nil {
		return err
	}
	be, closeFn, err := openPolicyBackend(&b)
	if err != nil {
		return err
	}
	defer closeFn()
	out, err := be.ExportPolicy(context.Background(), p, *format, filter)
	if err != nil {
		return err
	}
	for _, w := range out.Warnings {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}
	_, err = os.Stdout.WriteString(out.Config)
	return err
}

// defaultTwoWeeks widens the window, unless -from was given, to what learning needs.
func defaultTwoWeeks(f *filterFlags, fs *flag.FlagSet) {
	given := false
	fs.Visit(func(fl *flag.Flag) { given = given || fl.Name == "from" })
	if !given {
		f.from = "-14d"
	}
}

func runPolicyList(args []string) error {
	fs := flag.NewFlagSet("policy list", flag.ContinueOnError)
	var b backendFlags
	b.register(fs)
	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	be, closeFn, err := openPolicyBackend(&b)
	if err != nil {
		return err
	}
	defer closeFn()
	list, err := be.Policies(context.Background())
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(list)
}

func runPolicyShow(args []string) error {
	fs := flag.NewFlagSet("policy show", flag.ContinueOnError)
	var b backendFlags
	b.register(fs)
	id := fs.String("id", "", "policy ID; empty uses the active policy")
	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *id == "" && len(fs.Args()) > 0 {
		*id = fs.Arg(0)
	}
	be, closeFn, err := openPolicyBackend(&b)
	if err != nil {
		return err
	}
	defer closeFn()
	var p *policy.Policy
	if *id == "" {
		p, err = be.ActivePolicy(context.Background())
	} else {
		p, err = be.Policy(context.Background(), *id)
	}
	if err != nil {
		return err
	}
	if p == nil {
		return errors.New("no active policy")
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(p)
}

func runPolicySave(args []string, edit bool) error {
	fs := flag.NewFlagSet("policy save", flag.ContinueOnError)
	var b backendFlags
	b.register(fs)
	path := fs.String("file", "", "policy JSON file; - reads stdin")
	id := fs.String("id", "", "policy ID to replace (edit)")
	name := fs.String("name", "", "policy name")
	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *path == "" && len(fs.Args()) > 0 {
		*path = fs.Arg(0)
	}
	if *path == "" {
		return errors.New("usage: netgraph policy create|edit -file policy.json")
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
	p, err := policy.Parse(strings.NewReader(string(raw)))
	if err != nil {
		return err
	}
	if *id != "" {
		p.ID = *id
	}
	if *name != "" {
		p.Name = *name
	}
	if edit && p.ID == "" {
		return errors.New("policy edit needs -id")
	}
	be, closeFn, err := openPolicyBackendFor(&b, true)
	if err != nil {
		return err
	}
	defer closeFn()
	saved, err := be.SavePolicy(context.Background(), p)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(saved)
}

func runPolicyDelete(args []string) error {
	fs := flag.NewFlagSet("policy delete", flag.ContinueOnError)
	var b backendFlags
	b.register(fs)
	id := fs.String("id", "", "policy ID")
	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *id == "" && len(fs.Args()) > 0 {
		*id = fs.Arg(0)
	}
	if *id == "" {
		return errors.New("usage: netgraph policy delete -id ID")
	}
	be, closeFn, err := openPolicyBackendFor(&b, true)
	if err != nil {
		return err
	}
	defer closeFn()
	return be.DeletePolicy(context.Background(), *id)
}

func runPolicyActivate(args []string) error {
	fs := flag.NewFlagSet("policy activate", flag.ContinueOnError)
	var b backendFlags
	b.register(fs)
	id := fs.String("id", "", "policy ID")
	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *id == "" && len(fs.Args()) > 0 {
		*id = fs.Arg(0)
	}
	if *id == "" {
		return errors.New("usage: netgraph policy activate -id ID")
	}
	be, closeFn, err := openPolicyBackendFor(&b, true)
	if err != nil {
		return err
	}
	defer closeFn()
	return be.ActivatePolicy(context.Background(), *id)
}

func runPolicyExplain(args []string) error {
	fs := flag.NewFlagSet("policy explain", flag.ContinueOnError)
	var b backendFlags
	b.register(fs)
	path := fs.String("policy", "", "policy JSON file; empty uses the active policy")
	conn := fs.String("conn", "", "connection JSON, e.g. '{\"direction\":\"out\",\"name\":\"x\",\"ip\":\"1.2.3.4\",\"port\":\"443\",\"proto\":\"tcp\"}'")
	zone := fs.String("zone", "", "local zone")
	direction := fs.String("direction", "out", "out, in or local")
	name := fs.String("name", "", "remote name")
	ip := fs.String("ip", "", "remote address")
	port := fs.String("port", "", "port")
	proto := fs.String("proto", "", "protocol")
	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	var c policy.Conn
	if *conn != "" {
		if err := json.Unmarshal([]byte(*conn), &c); err != nil {
			return err
		}
	} else {
		c = policy.Conn{Zone: *zone, Direction: *direction, Name: *name, IP: *ip, Port: *port, Proto: *proto}
	}
	be, closeFn, err := openPolicyBackend(&b)
	if err != nil {
		return err
	}
	defer closeFn()
	var p *policy.Policy
	if *path != "" {
		raw, err := os.ReadFile(*path)
		if err != nil {
			return err
		}
		p, err = policy.Parse(strings.NewReader(string(raw)))
		if err != nil {
			return err
		}
	} else {
		p, err = be.ActivePolicy(context.Background())
		if err != nil {
			return err
		}
		if p == nil {
			return errors.New("no active policy and no -policy file")
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(p.Explain(c))
}

func runPolicyAudit(args []string) error {
	fs := flag.NewFlagSet("policy audit", flag.ContinueOnError)
	var b backendFlags
	b.register(fs)
	id := fs.String("id", "", "policy ID; empty uses the active policy")
	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	be, closeFn, err := openPolicyBackend(&b)
	if err != nil {
		return err
	}
	defer closeFn()
	var p *policy.Policy
	if *id == "" {
		p, err = be.ActivePolicy(context.Background())
	} else {
		p, err = be.Policy(context.Background(), *id)
	}
	if err != nil {
		return err
	}
	if p == nil {
		return errors.New("no active policy")
	}
	out, err := be.AuditPolicy(context.Background(), p)
	if err != nil {
		return err
	}
	return encode(out)
}
