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

type whatIfBackend interface {
	WhatIf(context.Context, *policy.Policy, model.Filter, string) (*model.WhatIfResult, error)
}

func runWhatIf(args []string) error {
	fs := flag.NewFlagSet("whatif", flag.ContinueOnError)
	var b backendFlags
	var f filterFlags
	b.register(fs)
	f.register(fs)
	policyPath := fs.String("policy", "", "policy JSON file")
	scope := fs.String("scope", "", "device:MAC, domain:name or ip:addr")
	out := fs.String("o", "table", "output: table, json")
	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *policyPath == "" {
		return errors.New("usage: netgraph whatif -policy policy.json [-from -7d]")
	}
	raw, err := os.ReadFile(*policyPath)
	if err != nil {
		return err
	}
	p, err := policy.Parse(strings.NewReader(string(raw)))
	if err != nil {
		return err
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
	wb, ok := be.(whatIfBackend)
	if !ok {
		return errors.New("this backend does not support what-if")
	}
	res, err := wb.WhatIf(context.Background(), p, filter, *scope)
	if err != nil {
		return err
	}
	if *out == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(res)
	}
	if *out != "table" {
		return fmt.Errorf("-o: %q is not table or json", *out)
	}
	fmt.Printf("POLICY %s  %s → %s\n", res.PolicyHash, ts(res.FromMS), ts(res.ToMS))
	fmt.Printf("connections %d · blocked %d · essential %d · unknown %d · unchanged %d · out of scope %d\n",
		res.Summary.Connections, res.Summary.Blocked, res.Summary.Essential, res.Summary.Unknown, res.Summary.Unchanged, res.Summary.OutOfScope)
	t := &table{head: []string{"CHANGE", "DEVICE", "DESTINATION", "PORT", "RULE", "SENT", "RECV", "REASON"}}
	for _, x := range res.Essential {
		t.add("essential", x.DeviceName, clip(x.Destination, 36), x.Port, x.Rule, model.FormatBytes(x.BytesOut), model.FormatBytes(x.BytesIn), x.Reason)
	}
	for _, x := range res.Blocked {
		t.add("blocked", x.DeviceName, clip(x.Destination, 36), x.Port, x.Rule, model.FormatBytes(x.BytesOut), model.FormatBytes(x.BytesIn), x.Reason)
	}
	for _, x := range res.Unknown {
		t.add("unknown", x.DeviceName, clip(x.Destination, 36), x.Port, x.Rule, model.FormatBytes(x.BytesOut), model.FormatBytes(x.BytesIn), x.Reason)
	}
	if err := t.write(os.Stdout, "table"); err != nil {
		return err
	}
	for _, g := range res.Gaps {
		fmt.Fprintf(os.Stderr, "gap: %s\n", g)
	}
	return nil
}
