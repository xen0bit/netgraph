package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/store"
)

const dbUsage = `usage: netgraph db <command> [flags]

commands:
  migrate          create or upgrade the database schema
  backup FILE      write a consistent copy of the database (safe while serving)
  retain           apply retention now (the server does this hourly)
  vacuum           rebuild the file to reclaim all free space (stop the server first)
`

func runDB(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, dbUsage)
		return errors.New("missing db command")
	}
	cmd, args := args[0], args[1:]
	fs := flag.NewFlagSet("db "+cmd, flag.ContinueOnError)
	db := fs.String("db", envOr("NETGRAPH_DB", "netgraph.db"), "database file; $NETGRAPH_DB")
	raw := fs.String("raw-retention", "14d", "retain: keep raw data this long")
	rollup := fs.String("rollup-retention", "180d", "retain: keep rollups and facts this long")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rawD, err := model.ParseDuration(*raw)
	if err != nil {
		return err
	}
	rollD, err := model.ParseDuration(*rollup)
	if err != nil {
		return err
	}
	cfg := store.Config{RawRetention: rawD, RollupRetention: rollD, Logger: quietLogger()}
	switch cmd {
	case "migrate":
		st, err := store.Open(*db, cfg)
		if err != nil {
			return err
		}
		return st.Close()
	case "backup":
		if fs.NArg() != 1 {
			return errors.New("usage: netgraph db backup [-db file] DEST")
		}
		st, err := store.OpenReadOnly(*db, cfg)
		if err != nil {
			return err
		}
		defer st.Close()
		if err := st.Backup(context.Background(), fs.Arg(0)); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "backed up %s to %s\n", *db, fs.Arg(0))
		return nil
	case "retain":
		st, err := store.Open(*db, cfg)
		if err != nil {
			return err
		}
		defer st.Close()
		r, err := st.Retain(context.Background())
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "deleted: %d flow records, %d lookups, %d answers, %d observations, %d facts, %d rollup rows, %d entities, %d Wi-Fi handshakes\n",
			r.Flows, r.DNS, r.Answers, r.Observations, r.Facts, r.Rollups, r.Entities, r.Handshakes)
		return nil
	case "vacuum":
		st, err := store.Open(*db, cfg)
		if err != nil {
			return err
		}
		defer st.Close()
		return st.Vacuum(context.Background())
	}
	fmt.Fprint(os.Stderr, dbUsage)
	return fmt.Errorf("unknown db command %q", cmd)
}
