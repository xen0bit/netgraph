// Package d2render compiles d2 scripts into SVG and terminal text. It is
// the only package that imports d2, which is large (it embeds a JavaScript
// engine for its layouts), so code that only builds graphs stays light.
package d2render

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"

	"oss.terrastruct.com/d2/d2graph"
	"oss.terrastruct.com/d2/d2layouts/d2dagrelayout"
	"oss.terrastruct.com/d2/d2layouts/d2elklayout"
	"oss.terrastruct.com/d2/d2lib"
	"oss.terrastruct.com/d2/d2renderers/d2ascii"
	"oss.terrastruct.com/d2/d2renderers/d2ascii/charset"
	"oss.terrastruct.com/d2/d2renderers/d2svg"
	"oss.terrastruct.com/d2/d2target"
	d2log "oss.terrastruct.com/d2/lib/log"
	"oss.terrastruct.com/d2/lib/textmeasure"

	"github.com/xen0bit/netgraph/internal/graph"
	"github.com/xen0bit/netgraph/internal/model"
)

// Options select the layout and look.
type Options struct {
	Layout string // "elk" (default) or "dagre"
	Theme  string // "dark" or "light"
	// Unicode selects box-drawing characters for text output; otherwise
	// plain ASCII.
	Unicode bool
}

// d2's layout engines are not safe for concurrent use.
var mu sync.Mutex

func logCtx() context.Context {
	return d2log.With(context.Background(), slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
}

func compile(script string, o Options) (*d2target.Diagram, error) {
	ctx := logCtx()
	ruler, err := textmeasure.NewRuler()
	if err != nil {
		return nil, err
	}
	layout := o.Layout
	if layout == "" {
		layout = "elk"
	}
	diagram, _, err := d2lib.Compile(ctx, script, &d2lib.CompileOptions{
		Layout: &layout,
		Ruler:  ruler,
		LayoutResolver: func(engine string) (d2graph.LayoutGraph, error) {
			switch engine {
			case "elk":
				return d2elklayout.DefaultLayout, nil
			case "dagre":
				return d2dagrelayout.DefaultLayout, nil
			}
			return nil, fmt.Errorf("unknown layout engine %q", engine)
		},
	}, nil)
	return diagram, err
}

// SVG renders a graph as SVG.
func SVG(g *model.Graph, o Options) ([]byte, error) {
	if len(g.Nodes) == 0 {
		return emptySVG, nil
	}
	return ScriptSVG(graph.RenderD2(g, graph.RenderOptions{Theme: o.Theme}), o)
}

// ScriptSVG renders a d2 script as SVG.
func ScriptSVG(script string, o Options) ([]byte, error) {
	mu.Lock()
	defer mu.Unlock()
	diagram, err := compile(script, o)
	if err != nil {
		return nil, err
	}
	pad := int64(d2svg.DEFAULT_PADDING)
	theme := int64(0)
	if o.Theme == "dark" {
		theme = 200
	}
	return d2svg.Render(diagram, &d2svg.RenderOpts{Pad: &pad, ThemeID: &theme})
}

// Text renders a graph as terminal text.
func Text(g *model.Graph, o Options) (string, error) {
	if len(g.Nodes) == 0 {
		return "(no activity in this window)\n", nil
	}
	return ScriptText(graph.RenderD2(g, graph.RenderOptions{ASCII: true}), o)
}

// ScriptText renders a d2 script as terminal text.
func ScriptText(script string, o Options) (string, error) {
	mu.Lock()
	defer mu.Unlock()
	diagram, err := compile(script, o)
	if err != nil {
		return "", err
	}
	cs := charset.ASCII
	if o.Unicode {
		cs = charset.Unicode
	}
	out, err := d2ascii.NewASCIIartist().Render(logCtx(), diagram, &d2ascii.RenderOpts{Charset: cs})
	if err != nil {
		return "", err
	}
	// The renderer pads every line to the canvas width; trailing spaces
	// only make terminals wrap.
	lines := strings.Split(string(out), "\n")
	for i, l := range lines {
		lines[i] = strings.TrimRight(l, " ")
	}
	return strings.TrimRight(strings.Join(lines, "\n"), "\n") + "\n", nil
}

var emptySVG = []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="400" height="80" viewBox="0 0 400 80"><text x="200" y="45" text-anchor="middle" font-family="sans-serif" font-size="14" fill="#6b7280">No activity in this window</text></svg>`)
