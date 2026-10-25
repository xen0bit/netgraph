// Package tui is netgraph's terminal UI: a time window over the graph,
// with tables of devices, connections, lookups and facts, a d2-drawn graph
// (or an outline of it), and a detail view for any entity. It talks to a
// model.Backend, so it works the same on a local database file and a
// remote server.
package tui

import (
	"errors"
	"io"
	"os"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"github.com/xen0bit/netgraph/internal/model"
)

// Options configure the TUI.
type Options struct {
	Backend model.Backend
	Source  string // shown in the header: the server URL or database file
	Filter  model.Filter
	Span    time.Duration // window length; default 1h, ending now
	Live    bool          // start following now
	Version string
	In      io.Reader
	Out     io.Writer
	// Now is the clock; tests set it.
	Now func() time.Time
	// SaveDir is where 's' writes graph files; default the working directory.
	SaveDir string
}

// Run opens the TUI and blocks until it is closed.
func Run(opts Options) error {
	if opts.Backend == nil {
		return errors.New("tui: no backend")
	}
	if opts.In == nil {
		opts.In = os.Stdin
	}
	if opts.Out == nil {
		opts.Out = os.Stdout
	}
	r := lipgloss.NewRenderer(opts.Out)
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		r.SetColorProfile(termenv.Ascii)
	}
	m := New(opts, newStyles(r, r.HasDarkBackground()))
	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithInput(opts.In), tea.WithOutput(opts.Out))
	_, err := p.Run()
	return err
}
