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
// web UI happened to load; each row is written as the database produces it.
func (s *Server) export(w http.ResponseWriter, r *http.Request) {
	f, ok := s.filter(w, r)
	if !ok {
		return
	}
	kind := r.URL.Query().Get("kind")
	ctx := r.Context()
	max := 0
	switch kind {
	case "":
		kind = "flows"
		fallthrough
	case "flows":
		max = 100000
		f.Limit = exportLimit(f.Limit, max)
	case "devices":
		max = 100000
		f.Limit = exportLimit(f.Limit, max)
	case "dns":
		max = 50000
		f.Limit = exportLimit(f.Limit, max)
	case "facts":
		max = 100000
		f.Limit = exportLimit(f.Limit, max)
	case "anomalies":
	case "wifi":
		max = 10000
		f.Limit = exportLimit(f.Limit, max)
	default:
		httpError(w, http.StatusBadRequest, fmt.Errorf("unknown export kind %q (devices, flows, dns, facts, anomalies, wifi)", kind))
		return
	}

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="netgraph-`+kind+`.csv"`)
	w.Header().Set("Cache-Control", "no-store")
	cw := csv.NewWriter(w)
	var err error
	switch kind {
	case "devices":
		var rows []model.Device
		rows, err = s.cfg.Store.Devices(ctx, f)
		if err == nil {
			err = writeCSV(ctx, cw, rows)
		}
	case "flows":
		err = writeCSVEach(ctx, cw, func(yield func(model.Flow) error) error {
			return s.cfg.Store.WalkFlows(ctx, f, yield)
		})
	case "dns":
		err = writeCSVEach(ctx, cw, func(yield func(model.DNSQuery) error) error {
			return s.cfg.Store.WalkDNS(ctx, f, yield)
		})
	case "facts":
		err = writeCSVEach(ctx, cw, func(yield func(model.Fact) error) error {
			return s.cfg.Store.WalkFacts(ctx, f, yield)
		})
	case "wifi":
		err = writeCSVEach(ctx, cw, func(yield func(model.WiFiNetwork) error) error {
			return s.cfg.Store.WalkWiFi(ctx, f, yield)
		})
	case "anomalies":
		var rep *model.AnomalyReport
		rep, err = s.cfg.Store.Anomalies(ctx, f)
		if err == nil {
			var rows []model.Anomaly
			if rep != nil {
				rows = rep.Anomalies
			}
			err = writeCSV(ctx, cw, rows)
		}
	}
	if err != nil {
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

// writeCSV writes a slice of structs as CSV.
func writeCSV[T any](ctx context.Context, cw *csv.Writer, rows []T) error {
	return writeCSVEach(ctx, cw, func(yield func(T) error) error {
		for _, row := range rows {
			if err := yield(row); err != nil {
				return err
			}
		}
		return nil
	})
}

// writeCSVEach writes a sequence of structs as CSV: one column per json field,
// in struct order. Times are ISO 8601; text a spreadsheet would evaluate as a
// formula is prefixed with a quote. The callback lets the caller stream rows
// from the database without retaining them.
func writeCSVEach[T any](ctx context.Context, cw *csv.Writer, walk func(func(T) error) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	t := reflect.TypeOf((*T)(nil)).Elem()
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
	n := 0
	err := walk(func(row T) error {
		if n%1024 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		n++
		v := reflect.ValueOf(row)
		rec := make([]string, len(fields))
		for j, f := range fields {
			rec[j] = csvValue(names[j], v.FieldByIndex(f.Index))
		}
		return cw.Write(rec)
	})
	if err != nil {
		return err
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
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return string(v.Bytes())
		}
		b, _ := json.Marshal(v.Interface())
		return csvText(string(b))
	case reflect.Map, reflect.Array, reflect.Struct:
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

// csvText neutralises a cell a spreadsheet could run as a formula, including
// one hidden behind leading whitespace.
func csvText(s string) string {
	for _, c := range s {
		switch c {
		case ' ', '\t', '\r', '\n':
			continue
		case '=', '+', '-', '@':
			return "'" + s
		default:
			return s
		}
	}
	return s
}
