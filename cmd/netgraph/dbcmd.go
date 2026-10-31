package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/xen0bit/netgraph/internal/asn"
	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/store"
)

const dbUsage = `usage: netgraph db <command> [flags]

commands:
  migrate          create or upgrade the database schema
  backup FILE      write a consistent copy of the database (safe while serving)
  retain           apply retention now (the server does this hourly)
  purge BEFORE     delete all data older than BEFORE (same time forms as queries)
  forget MAC       remove one device and everything attributed to it
  vacuum           rebuild the file to reclaim all free space (stop the server first)
  enrich           look up the network of remote ends stored without one (-asn-file; the server does this when it loads one)
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
	asnFile := fs.String("asn-file", envOr("NETGRAPH_ASN_FILE", ""), "enrich: an iptoasn.com ip2asn-combined.tsv(.gz) (default: the table built into release binaries); $NETGRAPH_ASN_FILE")
	dryRun := fs.Bool("dry-run", false, "purge/forget: count only, make no changes")
	force := fs.Bool("force", false, "backup: replace an existing destination")
	migrateBackup := fs.String("backup", "", "migrate: write a backup here before upgrading")
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
		if *migrateBackup != "" {
			if _, statErr := os.Stat(*db); statErr == nil {
				b, err := store.OpenBackup(*db, cfg)
				if err != nil {
					return err
				}
				err = b.Backup(context.Background(), *migrateBackup, store.BackupOptions{Force: *force})
				b.Close()
				if err != nil {
					return err
				}
				fmt.Fprintf(os.Stderr, "backed up %s to %s\n", *db, *migrateBackup)
			}
		}
		st, err := store.Open(*db, cfg)
		if err != nil {
			return err
		}
		return st.Close()
	case "backup":
		if fs.NArg() != 1 {
			return errors.New("usage: netgraph db backup [-db file] DEST")
		}
		st, err := store.OpenBackup(*db, cfg)
		if err != nil {
			return err
		}
		defer st.Close()
		if err := st.Backup(context.Background(), fs.Arg(0), store.BackupOptions{Force: *force}); err != nil {
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
		fmt.Fprintf(os.Stderr, "deleted: %d flow records, %d lookups, %d answers, %d observations, %d facts, %d rollup rows, %d entities, %d Wi-Fi handshakes, %d mutes\n",
			r.Flows, r.DNS, r.Answers, r.Observations, r.Facts, r.Rollups, r.Entities, r.Handshakes, r.Mutes)
		return nil
	case "purge":
		if fs.NArg() != 1 {
			return errors.New("usage: netgraph db purge [-db file] BEFORE")
		}
		before, err := model.ParseTime(fs.Arg(0), time.Now())
		if err != nil {
			return fmt.Errorf("before: %w", err)
		}
		st, err := store.Open(*db, cfg)
		if err != nil {
			return err
		}
		defer st.Close()
		r, err := st.PurgeBeforeWithOptions(context.Background(), before, store.PurgeOptions{DryRun: *dryRun})
		if err != nil {
			return err
		}
		verb := "deleted"
		if r.DryRun {
			verb = "would delete"
		}
		fmt.Fprintf(os.Stderr, "%s: %d flow records, %d connections, %d lookups, %d answers, %d observations, %d facts, %d rollup rows, %d entities, %d Wi-Fi records, %d mutes\n",
			verb, r.Flows, r.Connections, r.DNS, r.Answers, r.Observations, r.Facts, r.Rollups, r.Entities, r.Handshakes, r.Mutes)
		return nil
	case "forget":
		if fs.NArg() != 1 {
			return errors.New("usage: netgraph db forget [-db file] MAC")
		}
		st, err := store.Open(*db, cfg)
		if err != nil {
			return err
		}
		defer st.Close()
		r, err := st.ForgetDeviceWithOptions(context.Background(), fs.Arg(0), store.ForgetOptions{DryRun: *dryRun})
		if err != nil {
			return err
		}
		verb := "forgot"
		if r.DryRun {
			verb = "would forget"
		}
		fmt.Fprintf(os.Stderr, "%s %s: %d connections, %d flow records, %d lookups, %d observations, %d facts, %d rollup rows, %d entities, %d Wi-Fi records, %d mutes\n",
			verb, r.Device, r.Connections, r.Flows, r.DNS, r.Observations, r.Facts, r.Rollups, r.Entities, r.Handshakes+r.Groups, r.Mutes)
		return nil
	case "enrich":
		var table *asn.DB
		if *asnFile != "" {
			if table, err = asn.Load(*asnFile); err != nil {
				return err
			}
		} else if table, _, err = asn.Embedded(); err != nil {
			return err
		} else if table == nil {
			return errors.New("this build has no built-in ASN table: usage: netgraph db enrich [-db file] -asn-file ip2asn-combined.tsv.gz")
		}
		cfg.ASN = func() *asn.DB { return table }
		st, err := store.Open(*db, cfg)
		if err != nil {
			return err
		}
		defer st.Close()
		n, err := st.EnrichASN(context.Background())
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "looked up the network of %d rows\n", n)
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
