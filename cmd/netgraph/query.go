package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/store"
)

const queryUsage = `usage: netgraph query <what> [flags]

what:
  summary      headline numbers for the window
  devices      local devices active in the window
  flows        connections, with the traffic each carried inside the window
  dns          lookups and their answers
  facts        relationships that held in the window (addresses, hostnames,
               services, answers, fingerprints, ...)
  timeseries   traffic per step (-step)
  entity ID    everything about one entity: device:<mac>, ip:<addr>,
               domain:<name>, ...
  sensors      sensors that have sent data
  wifi         Wi-Fi networks seen by monitor-mode sensors
  anomalies    what stands out in the window, most severe first
`

func runQuery(args []string) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		fmt.Fprint(os.Stderr, queryUsage)
		return errors.New("missing what to query")
	}
	what, args := args[0], args[1:]
	var id string
	if what == "entity" {
		if len(args) == 0 || strings.HasPrefix(args[0], "-") {
			return errors.New("usage: netgraph query entity <kind:key> [flags]")
		}
		id, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("query "+what, flag.ContinueOnError)
	var b backendFlags
	var f filterFlags
	b.register(fs)
	f.register(fs)
	out := fs.String("o", "table", "output: table, json or csv")
	step := fs.String("step", "", "timeseries step, e.g. 5m (default: about 60 buckets)")
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
	w := os.Stdout
	var v any
	var t *table
	switch what {
	case "summary":
		s, err := be.Summary(ctx(), filter)
		if err != nil {
			return err
		}
		v = s
		if *out != "json" {
			return writeSummary(w, s)
		}
	case "devices":
		ds, err := be.Devices(ctx(), filter)
		if err != nil {
			return err
		}
		v, t = ds, devicesTable(ds)
	case "flows":
		fl, err := be.Flows(ctx(), filter)
		if err != nil {
			return err
		}
		v, t = fl, flowsTable(fl)
	case "dns":
		qs, err := be.DNS(ctx(), filter)
		if err != nil {
			return err
		}
		v, t = qs, dnsTable(qs)
	case "facts":
		fs, err := be.Facts(ctx(), filter)
		if err != nil {
			return err
		}
		v, t = fs, factsTable(fs)
	case "timeseries":
		var st = 0 * filter.To.Sub(filter.To)
		if *step != "" {
			if st, err = model.ParseDuration(*step); err != nil {
				return fmt.Errorf("-step: %w", err)
			}
		}
		series, err := be.Timeseries(ctx(), filter, st)
		if err != nil {
			return err
		}
		v, t = series, timeseriesTable(series)
	case "sensors":
		ss, err := be.Sensors(ctx())
		if err != nil {
			return err
		}
		v, t = ss, sensorsTable(ss)
	case "wifi":
		ns, err := be.WiFi(ctx(), filter)
		if err != nil {
			return err
		}
		v, t = ns, wifiTable(ns)
	case "anomalies":
		rep, err := be.Anomalies(ctx(), filter)
		if err != nil {
			return err
		}
		if rep.Learning {
			fmt.Fprintf(os.Stderr, "learning: checks that compare with history start %s after the first sensor reported\n", store.AnomalyHistory)
		}
		v, t = rep, anomaliesTable(rep.Anomalies)
	case "entity":
		d, err := be.Entity(ctx(), id, filter)
		if err != nil {
			return err
		}
		v = d
		if *out != "json" {
			return writeEntity(w, d)
		}
	default:
		fmt.Fprint(os.Stderr, queryUsage)
		return fmt.Errorf("unknown query %q", what)
	}
	if *out == "json" {
		return writeJSON(w, v)
	}
	return t.write(w, *out)
}

func writeSummary(w io.Writer, s *model.Summary) error {
	t := &table{head: []string{"WINDOW", ts(s.FromMS) + " → " + ts(s.ToMS)}}
	t.add("precision", s.Precision)
	t.add("devices", strconv.Itoa(s.Devices))
	t.add("connections", strconv.Itoa(s.Flows))
	t.add("peak concurrent", strconv.Itoa(s.PeakConns))
	t.add("dns queries", strconv.Itoa(s.DNSQueries))
	t.add("names", strconv.Itoa(s.Domains))
	t.add("remote addresses", strconv.Itoa(s.RemoteIPs))
	t.add("bytes up", model.FormatBytes(s.BytesOut))
	t.add("bytes down", model.FormatBytes(s.BytesIn))
	if s.RawFrom != 0 {
		t.add("exact data since", ts(s.RawFrom))
	}
	if s.OldestData != 0 {
		t.add("hourly data since", ts(s.OldestData))
	}
	return t.write(w, "table")
}

func devicesTable(ds []model.Device) *table {
	t := &table{head: []string{"DEVICE", "MAC", "VENDOR", "ADDRESSES", "HOSTNAMES", "SERVICES", "CONNS", "DNS", "UP", "DOWN", "ACTIVE"}}
	for _, d := range ds {
		vendor := d.VendorShort
		if d.Randomized {
			vendor = "(private MAC)"
		}
		if d.Role != "" {
			vendor = strings.TrimSpace(vendor + " [" + d.Role + "]")
		}
		t.add(clip(d.Label, 28), d.MAC, clip(vendor, 24), join(d.IPs, 2), clip(join(d.Hostnames, 2), 32), clip(join(d.Services, 2), 32),
			strconv.Itoa(d.Flows), strconv.Itoa(d.DNSQueries), model.FormatBytes(d.BytesOut), model.FormatBytes(d.BytesIn),
			ts(d.ActiveFrom)+" → "+ts(d.ActiveTo)[11:])
	}
	return t
}

func flowsTable(fl []model.Flow) *table {
	t := &table{head: []string{"OPENED", "DEVICE", "REMOTE", "NAME", "APP", "STATE", "UP", "DOWN", "LAST"}}
	for _, f := range fl {
		state := f.State
		if f.Closed {
			state += ",closed:" + f.EndReason
		}
		remote := fmt.Sprintf("%s:%d/%s", f.RemoteIP, f.RemotePort, f.Proto)
		if strings.Contains(f.RemoteIP, ":") {
			remote = fmt.Sprintf("[%s]:%d/%s", f.RemoteIP, f.RemotePort, f.Proto)
		}
		t.add(ts(f.FirstSeen), clip(firstNonEmpty(f.DeviceName, f.ClientIP), 24), remote, clip(f.Name, 36), f.App, state,
			model.FormatBytes(f.BytesOut), model.FormatBytes(f.BytesIn), ts(f.LastSeen)[11:])
	}
	return t
}

func dnsTable(qs []model.DNSQuery) *table {
	t := &table{head: []string{"TIME", "DEVICE", "TYPE", "NAME", "RCODE", "MS", "ANSWERS"}}
	for _, q := range qs {
		var ans []string
		for _, a := range q.Answers {
			ans = append(ans, fmt.Sprintf("%s(%ds)", a.Data, a.TTL))
		}
		ms := ""
		if q.LatencyMS > 0 {
			ms = strconv.FormatFloat(q.LatencyMS, 'f', 1, 64)
		}
		t.add(ts(q.TS), clip(firstNonEmpty(q.DeviceName, q.ClientIP), 24), q.QType, clip(q.QName, 40), q.RCode, ms, clip(strings.Join(ans, " "), 70))
	}
	return t
}

func factsTable(fs []model.Fact) *table {
	t := &table{head: []string{"REL", "FROM", "TO", "FIRST", "LAST", "COUNT", "SOURCE", "ATTRS"}}
	for _, f := range fs {
		var attrs []string
		for k, v := range f.Attrs {
			attrs = append(attrs, k+"="+v)
		}
		t.add(f.Rel, clip(firstNonEmpty(f.SrcLabel, f.Src), 30), clip(firstNonEmpty(f.DstLabel, f.Dst), 36), ts(f.FirstSeen), ts(f.LastSeen),
			strconv.Itoa(f.Count), f.Source, clip(strings.Join(attrs, " "), 40))
	}
	return t
}

func timeseriesTable(s *model.Timeseries) *table {
	t := &table{head: []string{"TIME", "UP", "DOWN", "NEW CONNS", "DNS", "DEVICES"}}
	for _, b := range s.Buckets {
		t.add(ts(b.TS), model.FormatBytes(b.BytesOut), model.FormatBytes(b.BytesIn), strconv.Itoa(b.FlowsNew), strconv.Itoa(b.DNSQueries), strconv.Itoa(b.Devices))
	}
	return t
}

func sensorsTable(ss []model.Sensor) *table {
	t := &table{head: []string{"SENSOR", "VERSION", "INTERFACES", "FIRST SEEN", "LAST SEEN", "PACKETS", "DROPS"}}
	for _, s := range ss {
		t.add(s.Name, s.Version, strings.Join(s.Interfaces, ","), ts(s.FirstSeen), ts(s.LastSeen), fmt.Sprint(s.Stats["packets"]), fmt.Sprint(s.Stats["kernel_drops"]))
	}
	return t
}

func wifiTable(ns []model.WiFiNetwork) *table {
	t := &table{head: []string{"SSID", "BSSID", "SECURITY", "CHANNEL", "CLIENTS", "FIRST SEEN", "LAST SEEN"}}
	for _, n := range ns {
		ch := ""
		if n.Channel != 0 {
			ch = strconv.Itoa(n.Channel)
		}
		t.add(clip(n.SSID, 32), n.BSSID, n.Security, ch, strconv.Itoa(n.Clients), ts(n.FirstSeen), ts(n.LastSeen))
	}
	return t
}

func anomaliesTable(as []model.Anomaly) *table {
	t := &table{head: []string{"SEVERITY", "TIME", "KIND", "DEVICE", "SUMMARY"}}
	for _, a := range as {
		t.add(a.Severity, ts(a.TS), a.Kind, clip(a.DeviceName, 32), a.Summary)
	}
	return t
}

func writeEntity(w io.Writer, d *model.EntityDetail) error {
	fmt.Fprintf(w, "%s  (%s)\nfirst seen %s, last seen %s\n", d.Label, d.ID, ts(d.FirstSeen), ts(d.LastSeen))
	for k, v := range d.Attrs {
		fmt.Fprintf(w, "  %s: %s\n", k, v)
	}
	if len(d.Facts) > 0 {
		fmt.Fprintln(w, "\nFACTS")
		_ = factsTable(d.Facts).write(w, "table")
	}
	if len(d.Flows) > 0 {
		fmt.Fprintln(w, "\nCONNECTIONS")
		_ = flowsTable(d.Flows).write(w, "table")
	}
	if len(d.DNS) > 0 {
		fmt.Fprintln(w, "\nDNS")
		_ = dnsTable(d.DNS).write(w, "table")
	}
	if len(d.Timeline) > 0 {
		fmt.Fprintln(w, "\nTIMELINE")
		t := &table{head: []string{"TIME", "EVENT", "DETAIL"}}
		for _, e := range d.Timeline {
			t.add(ts(e.TS), e.Type, clip(e.Detail, 100))
		}
		_ = t.write(w, "table")
	}
	return nil
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
