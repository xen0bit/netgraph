package api

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/xen0bit/netgraph/internal/buildinfo"
)

// ingestMetrics counts ingest requests for /metrics.
type ingestMetrics struct {
	batches, accepted, duplicates, errors atomic.Uint64
	nanos                                 atomic.Uint64 // time spent storing batches
}

func (m *ingestMetrics) observe(accepted, duplicates int, d time.Duration) {
	m.batches.Add(1)
	m.accepted.Add(uint64(accepted))
	m.duplicates.Add(uint64(duplicates))
	m.nanos.Add(uint64(d))
}

// sensorMetrics maps a sensor's reported stats to Prometheus series:
// the stat key, the metric name, its type and help text.
var sensorMetrics = []struct{ key, name, typ, help string }{
	{"packets", "netgraph_sensor_packets_total", "counter", "Packets captured since the sensor started."},
	{"bytes", "netgraph_sensor_bytes_total", "counter", "Bytes captured since the sensor started."},
	{"kernel_drops", "netgraph_sensor_kernel_drops_total", "counter", "Packets the kernel dropped before the sensor read them."},
	{"decode_errors", "netgraph_sensor_decode_errors_total", "counter", "Frames the sensor could not decode."},
	{"flows_active", "netgraph_sensor_flows_active", "gauge", "Connections in the sensor's flow table."},
	{"flows_evicted", "netgraph_sensor_flows_evicted_total", "counter", "Connections evicted from a full flow table."},
	{"events_queued", "netgraph_sensor_events_queued", "gauge", "Events waiting to be shipped."},
	{"events_dropped", "netgraph_sensor_events_dropped_total", "counter", "Events dropped because the spool was full."},
	{"batches_sent", "netgraph_sensor_batches_sent_total", "counter", "Batches delivered to the server."},
	{"send_errors", "netgraph_sensor_send_errors_total", "counter", "Failed deliveries (retried)."},
	{"heap_bytes", "netgraph_sensor_heap_bytes", "gauge", "Go heap in use on the sensor."},
}

// metrics serves Prometheus text exposition: the server's own counters,
// every sensor's last reported stats, and database size and contents.
func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var b strings.Builder
	m := func(name, typ, help string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
	}
	v := func(name string, labels []string, val float64) {
		b.WriteString(name)
		if len(labels) > 0 {
			b.WriteByte('{')
			for i := 0; i+1 < len(labels); i += 2 {
				if i > 0 {
					b.WriteByte(',')
				}
				fmt.Fprintf(&b, "%s=\"%s\"", labels[i], labelEscape(labels[i+1]))
			}
			b.WriteByte('}')
		}
		b.WriteByte(' ')
		b.WriteString(strconv.FormatFloat(val, 'g', -1, 64))
		b.WriteByte('\n')
	}

	m("netgraph_build_info", "gauge", "The server's version.")
	v("netgraph_build_info", []string{"version", buildinfo.Version, "commit", buildinfo.Commit}, 1)

	im := &s.ingestStats
	m("netgraph_ingest_batches_total", "counter", "Event batches stored.")
	v("netgraph_ingest_batches_total", nil, float64(im.batches.Load()))
	m("netgraph_ingest_events_total", "counter", "Events received, by result.")
	v("netgraph_ingest_events_total", []string{"result", "accepted"}, float64(im.accepted.Load()))
	v("netgraph_ingest_events_total", []string{"result", "duplicate"}, float64(im.duplicates.Load()))
	m("netgraph_ingest_errors_total", "counter", "Batches that failed to store.")
	v("netgraph_ingest_errors_total", nil, float64(im.errors.Load()))
	m("netgraph_ingest_seconds_total", "counter", "Time spent storing batches.")
	v("netgraph_ingest_seconds_total", nil, float64(im.nanos.Load())/1e9)

	if sensors, err := s.cfg.Store.Sensors(ctx); err == nil {
		sort.Slice(sensors, func(i, j int) bool { return sensors[i].Name < sensors[j].Name })
		m("netgraph_sensor_last_seen_timestamp_seconds", "gauge", "When the sensor last delivered a batch.")
		for _, sn := range sensors {
			v("netgraph_sensor_last_seen_timestamp_seconds", []string{"sensor", sn.Name}, float64(sn.LastSeen)/1e3)
		}
		m("netgraph_sensor_uptime_seconds", "gauge", "How long the sensor has been running.")
		for _, sn := range sensors {
			if f, ok := sn.Stats["uptime"].(float64); ok {
				v("netgraph_sensor_uptime_seconds", []string{"sensor", sn.Name}, f/1e9)
			}
		}
		for _, sm := range sensorMetrics {
			m(sm.name, sm.typ, sm.help)
			for _, sn := range sensors {
				if f, ok := sn.Stats[sm.key].(float64); ok {
					v(sm.name, []string{"sensor", sn.Name}, f)
				}
			}
		}
	}

	if counts, err := s.cfg.Store.EntityCounts(ctx); err == nil {
		m("netgraph_entities", "gauge", "Entities in the database, by kind.")
		kinds := make([]string, 0, len(counts))
		for k := range counts {
			kinds = append(kinds, k)
		}
		sort.Strings(kinds)
		for _, k := range kinds {
			v("netgraph_entities", []string{"kind", k}, float64(counts[k]))
		}
	}
	if path := s.cfg.Store.Path(); path != "" {
		var size int64
		for _, p := range []string{path, path + "-wal"} {
			if fi, err := os.Stat(p); err == nil {
				size += fi.Size()
			}
		}
		m("netgraph_db_size_bytes", "gauge", "Database file size, including the write-ahead log.")
		v("netgraph_db_size_bytes", nil, float64(size))
	}

	if s.cfg.Alerts != nil {
		st := s.cfg.Alerts()
		m("netgraph_alerts_total", "counter", "New-device alerts, by result.")
		v("netgraph_alerts_total", []string{"result", "sent"}, float64(st.Sent))
		v("netgraph_alerts_total", []string{"result", "failed"}, float64(st.Failed))
		v("netgraph_alerts_total", []string{"result", "dropped"}, float64(st.Dropped))
		v("netgraph_alerts_total", []string{"result", "learning"}, float64(st.Learning))
	}

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	m("go_goroutines", "gauge", "Goroutines in the server.")
	v("go_goroutines", nil, float64(runtime.NumGoroutine()))
	m("go_memstats_heap_alloc_bytes", "gauge", "Go heap in use by the server.")
	v("go_memstats_heap_alloc_bytes", nil, float64(ms.HeapAlloc))

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	io.WriteString(w, b.String())
}

// labelEscape escapes a label value for the text format. Sensor names come
// from sensors, so nothing is assumed about them.
func labelEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}
