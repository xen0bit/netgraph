package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/xen0bit/netgraph/internal/capture"
	"github.com/xen0bit/netgraph/internal/flow"
	"github.com/xen0bit/netgraph/internal/sensor"
	"github.com/xen0bit/netgraph/internal/store"
	"github.com/xen0bit/netgraph/internal/wire"
)

// batcher is an Emitter that ingests straight into a store.
type batcher struct {
	st      *store.Store
	sensor  string
	boot    string
	seq     uint64
	pending []wire.Event
	n       store.IngestResult
	err     error
}

func (b *batcher) Emit(ev wire.Event) {
	b.seq++
	ev.Seq = b.seq
	b.pending = append(b.pending, ev)
	if len(b.pending) >= 2000 {
		b.flush()
	}
}

func (b *batcher) flush() {
	if len(b.pending) == 0 || b.err != nil {
		return
	}
	r, err := b.st.Ingest(context.Background(), b.sensor, b.boot, b.pending)
	b.n.Accepted += r.Accepted
	b.n.Duplicates += r.Duplicates
	b.err = err
	b.pending = b.pending[:0]
}

func runImport(args []string) error {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	db := fs.String("db", envOr("NETGRAPH_DB", "netgraph.db"), "database file; $NETGRAPH_DB")
	name := fs.String("sensor", "import", "sensor name to record the capture under")
	active := fs.Duration("active-timeout", 30*time.Second, "flow interval length")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return errors.New("usage: netgraph import [-db file] [-sensor name] FILE.pcap [FILE...]")
	}
	st, err := store.Open(*db, store.Config{Logger: quietLogger()})
	if err != nil {
		return err
	}
	defer st.Close()
	for _, path := range fs.Args() {
		// The boot ID is the file's hash: importing the same file twice
		// is deduplicated like a retried batch.
		boot, err := fileHash(path)
		if err != nil {
			return err
		}
		src, err := capture.OpenFile(path)
		if err != nil {
			return err
		}
		b := &batcher{st: st, sensor: *name, boot: "import-" + boot}
		r := &sensor.Runner{
			Processor: sensor.NewProcessor(sensor.Config{Flow: flow.Config{ActiveTimeout: *active}, Logger: quietLogger()}, b),
			Out:       b,
			Hello:     wire.Hello{Name: *name, Version: "import", ActiveTimeout: *active},
		}
		if err := r.RunFile(context.Background(), src); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		b.flush()
		if b.err != nil {
			return fmt.Errorf("%s: %w", path, b.err)
		}
		fmt.Fprintf(os.Stderr, "%s: %d events ingested, %d already present\n", path, b.n.Accepted, b.n.Duplicates)
	}
	return nil
}

func fileHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)[:8]), nil
}
