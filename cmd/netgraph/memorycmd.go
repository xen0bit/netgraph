package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
)

type memoryBackend interface {
	CreateAnnotation(context.Context, model.Annotation) (*model.Annotation, error)
	CreateBookmark(context.Context, model.Bookmark) (*model.Bookmark, error)
}

func memoryFlags(name string) (*flag.FlagSet, *backendFlags, *string, *string, *string) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	var b backendFlags
	b.register(fs)
	at := fs.String("at", "now", "moment to mark")
	entity := fs.String("entity", "", "optional entity ID, e.g. device:aa:bb:cc:00:00:01")
	kind := fs.String("kind", "", "optional note kind")
	return fs, &b, at, entity, kind
}

func runNote(args []string) error {
	fs, b, at, entity, kind := memoryFlags("note")
	if err := fs.Parse(args); err != nil {
		return err
	}
	text := strings.TrimSpace(strings.Join(fs.Args(), " "))
	if text == "" {
		return errors.New("usage: netgraph note \"what changed\" [-at TIME] [-entity ID]")
	}
	when, err := model.ParseTime(*at, time.Now())
	if err != nil {
		return err
	}
	be, closeFn, err := b.open()
	if err != nil {
		return err
	}
	defer closeFn()
	mb, ok := be.(memoryBackend)
	if !ok {
		return errors.New("this backend does not support notes")
	}
	a, err := mb.CreateAnnotation(context.Background(), model.Annotation{TS: when.UnixMilli(), Entity: *entity, Kind: *kind, Text: text, Author: "cli"})
	if err != nil {
		return err
	}
	fmt.Printf("note #%d at %s\n", a.ID, ts(a.TS))
	return nil
}

func runBookmark(args []string) error {
	fs, b, at, entity, _ := memoryFlags("bookmark")
	if err := fs.Parse(args); err != nil {
		return err
	}
	name := strings.TrimSpace(strings.Join(fs.Args(), " "))
	if name == "" {
		return errors.New("usage: netgraph bookmark \"name\" [-at TIME] [-entity ID]")
	}
	when, err := model.ParseTime(*at, time.Now())
	if err != nil {
		return err
	}
	be, closeFn, err := b.open()
	if err != nil {
		return err
	}
	defer closeFn()
	mb, ok := be.(memoryBackend)
	if !ok {
		return errors.New("this backend does not support bookmarks")
	}
	bm, err := mb.CreateBookmark(context.Background(), model.Bookmark{TS: when.UnixMilli(), Entity: *entity, Name: name})
	if err != nil {
		return err
	}
	fmt.Printf("bookmark #%d at %s\n", bm.ID, ts(bm.TS))
	return nil
}
