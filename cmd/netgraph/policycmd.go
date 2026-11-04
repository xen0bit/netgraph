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
	"github.com/xen0bit/netgraph/internal/policy"
)

type policyBackend interface {
	LearnPolicy(context.Context, string, model.Filter) (*policy.Learned, error)
	ExportPolicy(context.Context, *policy.Policy, string, model.Filter) (*policy.Exported, error)
}

func runPolicy(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: netgraph policy learn|export")
	}
	switch args[0] {
	case "learn":
		return runPolicyLearn(args[1:])
	case "export":
		return runPolicyExport(args[1:])
	}
	return fmt.Errorf("policy: %q is not learn or export", args[0])
}

func openPolicyBackend(b *backendFlags) (policyBackend, func(), error) {
	be, closeFn, err := b.open()
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
