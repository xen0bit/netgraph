package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/xen0bit/netgraph/internal/buildinfo"
	"github.com/xen0bit/netgraph/internal/mcp"
)

// runMCP serves netgraph's read-only tools to an AI assistant, on stdin and stdout:
// the assistant starts this as a subprocess. Against a local database it opens it
// read-only; against a server it holds only the read token.
func runMCP(args []string) error {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	var b backendFlags
	b.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	be, closeFn, err := b.open()
	if err != nil {
		return err
	}
	defer closeFn()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	s := &mcp.Server{Backend: be, Version: buildinfo.Version}
	return s.Serve(ctx, os.Stdin, os.Stdout)
}
