package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/xen0bit/netgraph/internal/model"
)

type incidentBackend interface {
	Incidents(context.Context, string, int) ([]model.Incident, error)
	IncidentDetail(context.Context, int64) (*model.IncidentDetail, error)
	IncidentAutopsy(context.Context, int64) (*model.Autopsy, error)
	UpdateIncident(context.Context, int64, string, string, string, string, string) (*model.Incident, error)
	DeleteIncident(context.Context, int64) error
	ExportIncident(context.Context, int64) ([]byte, error)
}

const incidentUsage = `usage: netgraph incident <command> [flags]

commands:
  list [-status STATUS] [-limit N] [-o table|json]
  show ID [-o table|json]
  autopsy ID
  export ID [-o FILE]
  resolve ID
  reopen ID
  note ID "text"
  delete ID
`

func runIncident(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, incidentUsage)
		return errors.New("missing incident command")
	}
	cmd, args := args[0], args[1:]
	fs := flag.NewFlagSet("incident "+cmd, flag.ContinueOnError)
	var b backendFlags
	b.register(fs)
	status := fs.String("status", "", "list: open, acknowledged or resolved")
	limit := fs.Int("limit", 200, "list: maximum rows")
	out := fs.String("o", "table", "show/list/export: table, json, or file for export")
	if err := fs.Parse(args); err != nil {
		return err
	}
	be, closeFn, err := b.open()
	if err != nil {
		return err
	}
	defer closeFn()
	ib, ok := be.(incidentBackend)
	if !ok {
		return errors.New("this backend does not support incidents")
	}
	key, err := incidentID(fs, cmd)
	if err != nil {
		return err
	}
	ctx := context.Background()
	switch cmd {
	case "list":
		list, err := ib.Incidents(ctx, *status, *limit)
		if err != nil {
			return err
		}
		if *out == "json" {
			return writeJSON(os.Stdout, list)
		}
		t := &table{head: []string{"ID", "UPDATED", "STATUS", "SEVERITY", "KIND", "TITLE"}}
		for _, in := range list {
			t.add(strconv.FormatInt(in.ID, 10), ts(in.UpdatedMS), in.Status, in.Severity, in.Kind, clip(in.Title, 60))
		}
		return t.write(os.Stdout, "table")
	case "show":
		d, err := ib.IncidentDetail(ctx, key)
		if err != nil {
			return err
		}
		if *out == "json" {
			return writeJSON(os.Stdout, d)
		}
		fmt.Printf("#%d %s\n%s → %s · %s · %s\n%s\n", d.ID, d.Title, ts(d.StartMS), ts(d.EndMS), d.Status, d.Severity, d.Summary)
		for _, n := range d.Notes {
			fmt.Printf("  note %s: %s\n", ts(n.TS), n.Body)
		}
		return nil
	case "autopsy":
		a, err := ib.IncidentAutopsy(ctx, key)
		if err != nil {
			return err
		}
		fmt.Printf("autopsy #%d · %s → %s\n", a.Incident, ts(a.FromMS), ts(a.ToMS))
		for i, s := range a.Scenes {
			fmt.Printf("\n%d. %s  [%s]\n%s\n", i+1, s.Title, ts(s.AtMS), s.Narrative)
			for _, e := range s.Evidence {
				fmt.Printf("   - %s:%s %s\n", e.Kind, e.ID, e.Text)
			}
		}
		for _, g := range a.Gaps {
			fmt.Printf("gap: %s\n", g)
		}
		return nil
	case "export":
		b, err := ib.ExportIncident(ctx, key)
		if err != nil {
			return err
		}
		if *out != "json" && *out != "table" {
			return os.WriteFile(*out, b, 0o644)
		}
		_, err = os.Stdout.Write(b)
		return err
	case "resolve", "reopen", "acknowledge":
		next := map[string]string{"resolve": "resolved", "reopen": "open", "acknowledge": "acknowledged"}[cmd]
		in, err := ib.UpdateIncident(ctx, key, next, "", "", "", "")
		if err != nil {
			return err
		}
		fmt.Printf("#%d %s\n", in.ID, in.Status)
		return nil
	case "note":
		if fs.NArg() < 2 {
			return errors.New("usage: netgraph incident note ID \"text\"")
		}
		text := strings.Join(fs.Args()[1:], " ")
		in, err := ib.UpdateIncident(ctx, key, "", "", "", text, "cli")
		if err != nil {
			return err
		}
		fmt.Printf("#%d updated\n", in.ID)
		return nil
	case "delete":
		if err := ib.DeleteIncident(ctx, key); err != nil {
			return err
		}
		fmt.Printf("#%d deleted\n", key)
		return nil
	default:
		fmt.Fprint(os.Stderr, incidentUsage)
		return fmt.Errorf("unknown incident command %q", cmd)
	}
}

func incidentID(fs *flag.FlagSet, cmd string) (int64, error) {
	if cmd == "list" {
		return 0, nil
	}
	if fs.NArg() == 0 {
		return 0, fmt.Errorf("incident %s needs an ID", cmd)
	}
	id, err := strconv.ParseInt(fs.Arg(0), 10, 64)
	if err != nil || id <= 0 {
		return 0, errors.New("incident ID must be a positive integer")
	}
	return id, nil
}
