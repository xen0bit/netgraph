package tui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/xen0bit/netgraph/internal/model"
)

// parseFilter reads "key:value" tokens; a bare word filters by domain.
func parseFilter(s string) (model.Filter, error) {
	var f model.Filter
	for _, tok := range strings.Fields(s) {
		k, v, ok := strings.Cut(tok, ":")
		if !ok || strings.Count(tok, ":") > 1 && k != "device" && k != "ip" {
			// A bare word, or an IPv6 address / MAC typed bare.
			if strings.Count(tok, ":") >= 2 {
				if strings.Count(tok, ":") == 5 && len(tok) == 17 {
					f.Device = tok
				} else {
					f.IP = tok
				}
				continue
			}
			f.Domain = tok
			continue
		}
		switch k {
		case "device", "dev", "d":
			f.Device = v
		case "ip":
			f.IP = v
		case "domain", "name", "host":
			f.Domain = v
		case "port":
			n, err := strconv.Atoi(v)
			if err != nil {
				return f, fmt.Errorf("port: %q is not a number", v)
			}
			f.Port = n
		case "proto":
			f.Proto = v
		case "app":
			f.App = v
		case "dir", "direction":
			switch v {
			case model.DirOut, model.DirIn, model.DirLocal, model.DirExternal:
			default:
				return f, fmt.Errorf("dir: %q is not out, in, local or external", v)
			}
			f.Dir = v
		case "multicast":
			f.Multicast = v == "1" || v == "true" || v == "yes"
		default:
			return f, fmt.Errorf("unknown filter %q (device, ip, domain, port, proto, app, dir, multicast)", k)
		}
	}
	return f, nil
}

// filterString renders a filter back into the tokens parseFilter reads.
func filterString(f model.Filter) string {
	var parts []string
	add := func(k, v string) {
		if v != "" {
			parts = append(parts, k+":"+v)
		}
	}
	add("device", f.Device)
	add("ip", f.IP)
	add("domain", f.Domain)
	if f.Port != 0 {
		add("port", strconv.Itoa(f.Port))
	}
	add("proto", f.Proto)
	add("app", f.App)
	add("dir", f.Dir)
	if f.Multicast {
		add("multicast", "1")
	}
	return strings.Join(parts, " ")
}
