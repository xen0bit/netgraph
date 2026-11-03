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
	for _, tok := range splitFilter(s) {
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
		case "asn", "as":
			n, err := model.ParseASN(v)
			if err != nil {
				return f, fmt.Errorf("asn: %w", err)
			}
			f.ASN = n
		case "cc", "country":
			c, err := model.ParseCountry(v)
			if err != nil {
				return f, fmt.Errorf("cc: %w", err)
			}
			f.Country = c
		case "multicast":
			f.Multicast = v == "1" || v == "true" || v == "yes"
		default:
			return f, fmt.Errorf("unknown filter %q (device, ip, domain, port, proto, app, dir, asn, cc, multicast)", k)
		}
	}
	return f, nil
}

// splitFilter splits on spaces that are not inside single or double quotes,
// and honours backslash escapes, so a device label with spaces survives the
// round trip through the filter editor.
func splitFilter(s string) []string {
	var out []string
	var b strings.Builder
	var quote rune
	escaped := false
	for _, r := range s {
		switch {
		case escaped:
			b.WriteRune(r)
			escaped = false
		case r == '\\':
			escaped = true
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				b.WriteRune(r)
			}
		case r == '"' || r == '\'':
			quote = r
		case r == ' ' || r == '\t':
			if b.Len() > 0 {
				out = append(out, b.String())
				b.Reset()
			}
		default:
			b.WriteRune(r)
		}
	}
	if b.Len() > 0 {
		out = append(out, b.String())
	}
	return out
}

// quoteFilterValue wraps a value containing whitespace or quotes.
func quoteFilterValue(v string) string {
	if !strings.ContainsAny(v, " \t\"\\") {
		return v
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v) + `"`
}

// filterString renders a filter back into the tokens parseFilter reads.
func filterString(f model.Filter) string {
	var parts []string
	add := func(k, v string) {
		if v != "" {
			parts = append(parts, k+":"+quoteFilterValue(v))
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
	if f.ASN != 0 {
		add("asn", strconv.FormatUint(uint64(f.ASN), 10))
	}
	add("cc", f.Country)
	if f.Multicast {
		add("multicast", "1")
	}
	return strings.Join(parts, " ")
}
