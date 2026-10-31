package api

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
)

// export serves every field of one table as CSV, for the rows the window
// selects. It exists so a large window does not depend on how many rows the
// web UI happened to load; the CSV writer streams to the response.
func (s *Server) export(w http.ResponseWriter, r *http.Request) {
	f, ok := s.filter(w, r)
	if !ok {
		return
	}
	kind := r.URL.Query().Get("kind")
	var (
		rows any
		err  error
		max  int
	)
	switch kind {
	case "devices":
		max = 100000
		f.Limit = exportLimit(f.Limit, max)
		var v []model.Device
		v, err = s.cfg.Store.Devices(r.Context(), f)
		rows = v
	case "flows", "":
		kind, max = "flows", 100000
		f.Limit = exportLimit(f.Limit, max)
		var v []model.Flow
		v, err = s.cfg.Store.Flows(r.Context(), f)
		rows = v
	case "dns":
		max = 50000
		f.Limit = exportLimit(f.Limit, max)
		var v []model.DNSQuery
		v, err = s.cfg.Store.DNS(r.Context(), f)
		rows = v
	case "facts":
		max = 100000
		f.Limit = exportLimit(f.Limit, max)
		var v []model.Fact
		v, err = s.cfg.Store.Facts(r.Context(), f)
		rows = v
	case "anomalies":
		var rep *model.AnomalyReport
		rep, err = s.cfg.Store.Anomalies(r.Context(), f)
		if rep != nil {
			rows = rep.Anomalies
		} else {
			rows = []model.Anomaly{}
		}
	case "wifi":
		max = 10000
		f.Limit = exportLimit(f.Limit, max)
		var v []model.WiFiNetwork
		v, err = s.cfg.Store.WiFi(r.Context(), f)
		rows = v
	default:
		httpError(w, http.StatusBadRequest, fmt.Errorf("unknown export kind %q (devices, flows, dns, facts, anomalies, wifi)", kind))
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="netgraph-`+kind+`.csv"`)
	cw := csv.NewWriter(w)
	if err := writeCSV(r.Context(), cw, rows); err != nil {
		s.log.Error("export csv", "kind", kind, "err", err)
	}
	cw.Flush()
}

func exportLimit(n, max int) int {
	if n <= 0 || n > max {
		return max
	}
	return n
}

// writeCSV writes a slice of structs as CSV: one column per json field, in
// struct order. Times are ISO 8601; text a spreadsheet would evaluate as a
// formula is prefixed with a quote.
func writeCSV(ctx context.Context, cw *csv.Writer, rows any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	rv := reflect.ValueOf(rows)
	if rv.Kind() != reflect.Slice {
		return fmt.Errorf("export: %T is not a slice", rows)
	}
	t := rv.Type().Elem()
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return fmt.Errorf("export: %s is not a struct", t)
	}
	fields := make([]reflect.StructField, 0, t.NumField())
	names := make([]string, 0, t.NumField())
	for i := range t.NumField() {
		f := t.Field(i)
		if f.PkgPath != "" {
			continue
		}
		tag := strings.Split(f.Tag.Get("json"), ",")[0]
		if tag == "-" {
			continue
		}
		if tag == "" {
			tag = strings.ToLower(f.Name)
		}
		fields = append(fields, f)
		names = append(names, tag)
	}
	if err := cw.Write(names); err != nil {
		return err
	}
	for i := 0; i < rv.Len(); i++ {
		if i%1024 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		v := rv.Index(i)
		rec := make([]string, len(fields))
		for j, f := range fields {
			rec[j] = csvValue(names[j], v.FieldByIndex(f.Index))
		}
		if err := cw.Write(rec); err != nil {
			return err
		}
	}
	return cw.Error()
}

func csvValue(name string, v reflect.Value) string {
	if !v.IsValid() {
		return ""
	}
	for v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface {
		if v.IsNil() {
			return ""
		}
		v = v.Elem()
	}
	switch v.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n := v.Int()
		if isTimeField(name) && n > 0 {
			return time.UnixMilli(n).UTC().Format(time.RFC3339Nano)
		}
		return strconv.FormatInt(n, 10)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return strconv.FormatUint(v.Uint(), 10)
	case reflect.Float32, reflect.Float64:
		return strconv.FormatFloat(v.Float(), 'f', -1, 64)
	case reflect.Bool:
		return strconv.FormatBool(v.Bool())
	case reflect.String:
		return csvText(v.String())
	case reflect.Slice, reflect.Map, reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return string(v.Bytes())
		}
		b, _ := json.Marshal(v.Interface())
		return csvText(string(b))
	default:
		b, _ := json.Marshal(v.Interface())
		return csvText(string(b))
	}
}

func isTimeField(name string) bool {
	switch name {
	case "ts", "first_seen", "last_seen", "active_from", "active_to", "expires":
		return true
	}
	return false
}

// csvText neutralises a cell a spreadsheet could run as a formula.
func csvText(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}
