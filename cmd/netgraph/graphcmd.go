package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/xen0bit/netgraph/internal/graph"
	"github.com/xen0bit/netgraph/internal/graph/d2render"
	"github.com/xen0bit/netgraph/internal/model"
)

func runGraph(args []string) error {
	fs := flag.NewFlagSet("graph", flag.ContinueOnError)
	var b backendFlags
	var f filterFlags
	b.register(fs)
	f.register(fs)
	out := fs.String("o", "-", "output file: .svg, .d2, .txt or .json; - prints text to stdout")
	collapse := fs.Bool("collapse", true, "fold remote addresses into the names they were reached by")
	top := fs.Int("top", 15, "keep each device's N busiest destinations (-1: all)")
	identity := fs.Bool("identity", false, "draw hostnames, services, fingerprints and vendors as nodes")
	dns := fs.Bool("dns", true, "draw lookups and answers")
	layout := fs.String("layout", "elk", "layout engine: elk or dagre")
	theme := fs.String("theme", "light", "SVG theme: light or dark")
	ascii := fs.Bool("ascii", false, "plain ASCII text instead of box-drawing characters")
	if err := fs.Parse(args); err != nil {
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
	g, err := be.Graph(ctx(), filter, model.GraphOptions{Collapse: *collapse, TopN: *top, Identity: *identity, DNS: *dns})
	if err != nil {
		return err
	}
	ro := d2render.Options{Layout: *layout, Theme: *theme, Unicode: !*ascii}
	var data []byte
	switch ext := strings.ToLower(filepath.Ext(*out)); {
	case *out == "-" || ext == ".txt":
		txt, err := d2render.Text(g, ro)
		if err != nil {
			return err
		}
		data = []byte(txt)
	case ext == ".svg":
		if data, err = d2render.SVG(g, ro); err != nil {
			return err
		}
	case ext == ".d2":
		data = []byte(graph.RenderD2(g, graph.RenderOptions{Theme: *theme}))
	case ext == ".json":
		f, err := os.Create(*out)
		if err != nil {
			return err
		}
		defer f.Close()
		return writeJSON(f, g)
	default:
		return fmt.Errorf("-o %s: use .svg, .d2, .txt, .json or -", *out)
	}
	if *out == "-" {
		_, err = os.Stdout.Write(data)
		return err
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s: %d nodes, %d edges (%s)\n", *out, len(g.Nodes), len(g.Edges), g.Precision)
	return nil
}
