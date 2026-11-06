package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/xen0bit/netgraph/internal/model"
)

type profileBackend interface {
	Profiles(context.Context) ([]model.Profile, error)
	Profile(context.Context, int64) (*model.Profile, error)
	SaveProfile(context.Context, *model.Profile) (*model.Profile, error)
	DeleteProfile(context.Context, int64) error
	ActivateProfile(context.Context, int64) error
	EvaluateProfile(context.Context) (*model.Profile, error)
	NetworkContext(context.Context) (*model.NetworkContext, error)
	NetworkTriggers(context.Context) ([]model.NetworkTrigger, error)
	SaveNetworkTrigger(context.Context, *model.NetworkTrigger) (*model.NetworkTrigger, error)
	DeleteNetworkTrigger(context.Context, int64) error
}

func runProfile(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: netgraph profile list|show|add|delete|activate|current|evaluate|triggers|trigger-add|trigger-delete")
	}
	switch args[0] {
	case "list":
		return runProfileList(args[1:])
	case "show":
		return runProfileShow(args[1:])
	case "add":
		return runProfileAdd(args[1:])
	case "delete":
		return runProfileDelete(args[1:])
	case "activate":
		return runProfileActivate(args[1:])
	case "current":
		return runProfileCurrent(args[1:])
	case "evaluate":
		return runProfileEvaluate(args[1:])
	case "triggers":
		return runProfileTriggers(args[1:])
	case "trigger-add":
		return runProfileTriggerAdd(args[1:])
	case "trigger-delete":
		return runProfileTriggerDelete(args[1:])
	}
	return fmt.Errorf("profile: %q is not a command", args[0])
}

func openProfileBackend(b *backendFlags, write bool) (profileBackend, func(), error) {
	var be model.Backend
	var closeFn func()
	var err error
	if write {
		be, closeFn, err = b.openWritable()
	} else {
		be, closeFn, err = b.open()
	}
	if err != nil {
		return nil, nil, err
	}
	pb, ok := be.(profileBackend)
	if !ok {
		closeFn()
		return nil, nil, errors.New("this backend can't do profiles")
	}
	return pb, closeFn, nil
}

func runProfileList(args []string) error {
	fs := flag.NewFlagSet("profile list", flag.ContinueOnError)
	var b backendFlags
	b.register(fs)
	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	be, closeFn, err := openProfileBackend(&b, false)
	if err != nil {
		return err
	}
	defer closeFn()
	out, err := be.Profiles(context.Background())
	if err != nil {
		return err
	}
	return encode(out)
}

func runProfileShow(args []string) error {
	fs := flag.NewFlagSet("profile show", flag.ContinueOnError)
	var b backendFlags
	b.register(fs)
	id := fs.Int64("id", 0, "profile ID")
	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	be, closeFn, err := openProfileBackend(&b, false)
	if err != nil {
		return err
	}
	defer closeFn()
	out, err := be.Profile(context.Background(), *id)
	if err != nil {
		return err
	}
	return encode(out)
}

func runProfileAdd(args []string) error {
	fs := flag.NewFlagSet("profile add", flag.ContinueOnError)
	var b backendFlags
	b.register(fs)
	name := fs.String("name", "", "profile name")
	desc := fs.String("description", "", "description")
	mode := fs.String("mode", "alert", "alert, silent-allow or silent-deny")
	def := fs.Bool("default", false, "use for unknown networks")
	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *name == "" {
		return errors.New("usage: netgraph profile add -name NAME [-mode alert]")
	}
	be, closeFn, err := openProfileBackend(&b, true)
	if err != nil {
		return err
	}
	defer closeFn()
	out, err := be.SaveProfile(context.Background(), &model.Profile{Name: *name, Description: *desc, Mode: *mode, IsDefault: *def})
	if err != nil {
		return err
	}
	return encode(out)
}

func runProfileDelete(args []string) error {
	fs := flag.NewFlagSet("profile delete", flag.ContinueOnError)
	var b backendFlags
	b.register(fs)
	id := fs.Int64("id", 0, "profile ID")
	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	be, closeFn, err := openProfileBackend(&b, true)
	if err != nil {
		return err
	}
	defer closeFn()
	return be.DeleteProfile(context.Background(), *id)
}

func runProfileActivate(args []string) error {
	fs := flag.NewFlagSet("profile activate", flag.ContinueOnError)
	var b backendFlags
	b.register(fs)
	id := fs.Int64("id", 0, "profile ID")
	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	be, closeFn, err := openProfileBackend(&b, true)
	if err != nil {
		return err
	}
	defer closeFn()
	return be.ActivateProfile(context.Background(), *id)
}

func runProfileCurrent(args []string) error {
	fs := flag.NewFlagSet("profile current", flag.ContinueOnError)
	var b backendFlags
	b.register(fs)
	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	be, closeFn, err := openProfileBackend(&b, false)
	if err != nil {
		return err
	}
	defer closeFn()
	nc, err := be.NetworkContext(context.Background())
	if err != nil {
		return err
	}
	return encode(nc)
}

func runProfileEvaluate(args []string) error {
	fs := flag.NewFlagSet("profile evaluate", flag.ContinueOnError)
	var b backendFlags
	b.register(fs)
	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	be, closeFn, err := openProfileBackend(&b, true)
	if err != nil {
		return err
	}
	defer closeFn()
	out, err := be.EvaluateProfile(context.Background())
	if err != nil {
		return err
	}
	return encode(out)
}

func runProfileTriggers(args []string) error {
	fs := flag.NewFlagSet("profile triggers", flag.ContinueOnError)
	var b backendFlags
	b.register(fs)
	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	be, closeFn, err := openProfileBackend(&b, false)
	if err != nil {
		return err
	}
	defer closeFn()
	out, err := be.NetworkTriggers(context.Background())
	if err != nil {
		return err
	}
	return encode(out)
}

func runProfileTriggerAdd(args []string) error {
	fs := flag.NewFlagSet("profile trigger-add", flag.ContinueOnError)
	var b backendFlags
	b.register(fs)
	profile := fs.Int64("profile", 0, "profile ID")
	sig := fs.String("signature", "", "network signature pattern")
	action := fs.String("action", "activate", "activate, deactivate, ask or none")
	mode := fs.String("mode", "", "optional mode override")
	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *profile == 0 || *sig == "" {
		return errors.New("usage: netgraph profile trigger-add -profile N -signature '{\"ssid\":\"home\"}'")
	}
	be, closeFn, err := openProfileBackend(&b, true)
	if err != nil {
		return err
	}
	defer closeFn()
	out, err := be.SaveNetworkTrigger(context.Background(), &model.NetworkTrigger{
		ProfileID: *profile, Signature: *sig, Action: *action, Mode: *mode, Enabled: true,
	})
	if err != nil {
		return err
	}
	return encode(out)
}

func runProfileTriggerDelete(args []string) error {
	fs := flag.NewFlagSet("profile trigger-delete", flag.ContinueOnError)
	var b backendFlags
	b.register(fs)
	id := fs.Int64("id", 0, "trigger ID")
	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	be, closeFn, err := openProfileBackend(&b, true)
	if err != nil {
		return err
	}
	defer closeFn()
	return be.DeleteNetworkTrigger(context.Background(), *id)
}

var _ = json.Marshal
var _ = os.Stdout
