package store

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/policy"
)

// maxPolicyFlows bounds what learning and exporting read.
const maxPolicyFlows = 100000

// LearnPolicy proposes the least a device needs, from what it did in a window.
func (s *Store) LearnPolicy(ctx context.Context, device string, f model.Filter) (*policy.Learned, error) {
	mac := strings.TrimPrefix(device, model.KindDevice+":")
	if mac == "" {
		return nil, fmt.Errorf("%w: which device?", ErrInvalid)
	}
	from, to := s.window(f)
	f.Device = mac
	f.Limit = maxPolicyFlows
	flows, err := s.Flows(ctx, f)
	if err != nil {
		return nil, err
	}
	id := model.EntityID(model.KindDevice, mac)
	out := &policy.Learned{Device: id, FromMS: from, ToMS: to}
	seen := make([]policy.Seen, 0, len(flows))
	earliest := int64(0)
	for _, fl := range flows {
		// Filtering by device also finds connections to it from others: those are the
		// other device's to be allowed.
		if fl.Device != id || fl.Direction == model.DirExternal {
			continue
		}
		if earliest == 0 || fl.FirstSeen < earliest {
			earliest = fl.FirstSeen
		}
		seen = append(seen, policy.Seen{
			Direction: fl.Direction, Name: firstNonEmpty(fl.Name, fl.RemoteIP), IP: fl.RemoteIP,
			Port: strconv.Itoa(servicePort(fl)), Proto: fl.Proto, Bytes: fl.BytesOut + fl.BytesIn,
		})
	}
	out.Connections = len(seen)
	if len(seen) == 0 {
		return nil, fmt.Errorf("%w: no connections from this device in that window, so there's nothing to learn from", ErrNotFound)
	}
	p, gaps := policy.Learn(id, seen)
	out.Policy = p
	out.Gaps = gaps
	if len(flows) >= maxPolicyFlows {
		out.Gaps = append(out.Gaps, fmt.Sprintf("only the latest %d connections were read", maxPolicyFlows))
	}
	if earliest > from+int64(24*time.Hour/time.Millisecond) {
		out.Gaps = append(out.Gaps, "records only go back to "+time.UnixMilli(earliest).UTC().Format("2006-01-02")+", so anything it does less often than that isn't here")
	}
	out.Gaps = append(out.Gaps, "this is what it did, not what it needs: something it does monthly, or that didn't happen in this window, would stop working")
	return out, nil
}

// ExportPolicy generates a firewall's configuration from a policy, resolving devices and names
// to the addresses seen in the window. It only reads.
func (s *Store) ExportPolicy(ctx context.Context, p *policy.Policy, format string, f model.Filter) (*policy.Exported, error) {
	if !policy.ValidFormat(format) {
		return nil, fmt.Errorf("%w: format %q is not nftables, openwrt or opnsense", ErrInvalid, format)
	}
	ff := f
	ff.Limit = maxPolicyFlows
	devices, err := s.Devices(ctx, ff)
	if err != nil {
		return nil, err
	}
	var obs policy.Observed
	for _, d := range devices {
		obs.Devices = append(obs.Devices, policy.ObservedDevice{ID: d.ID, Label: d.Label, Role: d.Role, IPs: d.IPs})
	}
	flows, err := s.Flows(ctx, ff)
	if err != nil {
		return nil, err
	}
	type remote struct{ name, ip string }
	done := map[remote]bool{}
	for _, fl := range flows {
		if fl.RemoteIP == "" {
			continue
		}
		k := remote{firstNonEmpty(fl.Name, fl.RemoteIP), fl.RemoteIP}
		if done[k] {
			continue
		}
		done[k] = true
		obs.Remotes = append(obs.Remotes, policy.ObservedRemote{Name: k.name, IP: k.ip, ASN: fl.ASN, Country: fl.Country})
	}
	out, err := policy.ExportPolicy(p, format, obs, s.cfg.Now().UTC().Format("2006-01-02 15:04 UTC"))
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalid, err.Error())
	}
	if len(flows) >= maxPolicyFlows {
		out.Warnings = append(out.Warnings, fmt.Sprintf("only the latest %d connections were read for addresses", maxPolicyFlows))
	}
	return out, nil
}
