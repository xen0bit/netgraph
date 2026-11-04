package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/xen0bit/netgraph/internal/archive"
	"github.com/xen0bit/netgraph/internal/model"
)

func runArchive(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: netgraph archive list|read -dir DIR")
	}
	cmd, args := args[0], args[1:]
	fs := flag.NewFlagSet("archive "+cmd, flag.ContinueOnError)
	dir := fs.String("dir", envOr("NETGRAPH_ARCHIVE_DIR", ""), "the archive directory; $NETGRAPH_ARCHIVE_DIR")
	tableName := fs.String("table", "", "read: traffic_hourly, dns_hourly, connections or dns (default all)")
	from := fs.String("from", "", "read: at or after this: -30d, RFC 3339, unix ms")
	to := fs.String("to", "", "read: before this, same forms")
	device := fs.String("device", "", "read: one device, by MAC")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		return errors.New("-dir is needed: where -archive-dir points on the server")
	}
	d := archive.Dir{Path: *dir}
	switch cmd {
	case "list":
		files, err := d.List()
		if err != nil {
			return err
		}
		t := &table{head: []string{"DAY", "TABLE", "SIZE"}}
		var total int64
		for _, f := range files {
			t.add(f.Day.Format("2006-01-02"), f.Table, model.FormatBytes(uint64(f.Bytes)))
			total += f.Bytes
		}
		if err := t.write(os.Stdout, "table"); err != nil {
			return err
		}
		fmt.Printf("%d files, %s\n", len(files), model.FormatBytes(uint64(total)))
		return nil
	case "read":
		now := time.Now()
		q := archive.Query{Table: *tableName, Device: strings.ToLower(*device)}
		var err error
		if *from != "" {
			if q.From, err = model.ParseTime(*from, now); err != nil {
				return fmt.Errorf("-from: %w", err)
			}
		}
		if *to != "" {
			if q.To, err = model.ParseTime(*to, now); err != nil {
				return fmt.Errorf("-to: %w", err)
			}
		}
		return d.Read(q, func(line string) error {
			_, err := fmt.Fprintln(os.Stdout, line)
			return err
		})
	}
	return fmt.Errorf("archive: %q is not list or read", cmd)
}
