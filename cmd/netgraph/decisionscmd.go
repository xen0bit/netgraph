package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/xen0bit/netgraph/internal/model"
)

type decisionBackend interface {
	Decisions(context.Context, string) ([]model.PolicyDecision, error)
	ScanDecisions(context.Context, model.Filter, int) (int, error)
	AnswerDecision(context.Context, int64, string, string, string, string) (*model.PolicyDecision, error)
	ResetDecision(context.Context, int64) error
}

func runDecisions(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: netgraph decisions list|scan|allow|deny|rule|reset")
	}
	switch args[0] {
	case "list":
		return runDecisionsList(args[1:])
	case "scan":
		return runDecisionsScan(args[1:])
	case "allow", "deny", "rule":
		return runDecisionAnswer(args[1:], args[0])
	case "reset":
		return runDecisionReset(args[1:])
	}
	return fmt.Errorf("decisions: %q is not a command", args[0])
}

func openDecisionBackend(b *backendFlags, write bool) (decisionBackend, func(), error) {
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
	db, ok := be.(decisionBackend)
	if !ok {
		closeFn()
		return nil, nil, errors.New("this backend can't do decisions")
	}
	return db, closeFn, nil
}

func runDecisionsList(args []string) error {
	fs := flag.NewFlagSet("decisions list", flag.ContinueOnError)
	var b backendFlags
	b.register(fs)
	status := fs.String("status", "open", "open, allowed, denied, rule-created, expired or all")
	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *status == "all" {
		*status = ""
	}
	be, closeFn, err := openDecisionBackend(&b, false)
	if err != nil {
		return err
	}
	defer closeFn()
	out, err := be.Decisions(context.Background(), *status)
	if err != nil {
		return err
	}
	return encode(out)
}

func runDecisionsScan(args []string) error {
	fs := flag.NewFlagSet("decisions scan", flag.ContinueOnError)
	var b backendFlags
	var f filterFlags
	b.register(fs)
	f.register(fs)
	limit := fs.Int("limit", 2000, "maximum connections to evaluate")
	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	filter, err := f.filter()
	if err != nil {
		return err
	}
	be, closeFn, err := openDecisionBackend(&b, true)
	if err != nil {
		return err
	}
	defer closeFn()
	n, err := be.ScanDecisions(context.Background(), filter, *limit)
	if err != nil {
		return err
	}
	return encode(map[string]int{"created": n})
}

func runDecisionAnswer(args []string, answer string) error {
	fs := flag.NewFlagSet("decisions "+answer, flag.ContinueOnError)
	var b backendFlags
	b.register(fs)
	id := fs.Int64("id", 0, "decision ID")
	action := fs.String("action", "deny", "with rule: the new rule's action, allow or deny")
	note := fs.String("note", "", "note")
	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *id == 0 {
		return errors.New("usage: netgraph decisions allow|deny|rule -id N [-action allow|deny]")
	}
	be, closeFn, err := openDecisionBackend(&b, true)
	if err != nil {
		return err
	}
	defer closeFn()
	if answer != "rule" {
		*action = ""
	}
	d, err := be.AnswerDecision(context.Background(), *id, answer, *action, localActor(), *note)
	if err != nil {
		return err
	}
	return encode(d)
}

func runDecisionReset(args []string) error {
	fs := flag.NewFlagSet("decision reset", flag.ContinueOnError)
	var b backendFlags
	b.register(fs)
	id := fs.Int64("id", 0, "decision ID")
	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	be, closeFn, err := openDecisionBackend(&b, true)
	if err != nil {
		return err
	}
	defer closeFn()
	return be.ResetDecision(context.Background(), *id)
}

// localActor names who answered from this command line when it works on the
// database directly; through -server, the server records the token's identity.
func localActor() string {
	if u := os.Getenv("USER"); u != "" {
		return "cli:" + u
	}
	return "cli"
}
