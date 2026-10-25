package wire

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/klauspost/compress/zstd"
)

// HTTP headers that carry the batch envelope. The body is the events alone,
// so a batch can be inspected with `zstd -d | jq`.
const (
	HeaderSensor  = "X-Netgraph-Sensor"  // sensor name
	HeaderBoot    = "X-Netgraph-Boot"    // random per sensor start; scopes Seq
	HeaderVersion = "X-Netgraph-Version" // schema Version
	ContentType   = "application/x-ndjson"
	Encoding      = "zstd"
)

// MaxBatchBytes bounds a decoded batch. A sensor never builds one near this;
// it exists so a hostile or broken client cannot make the server inflate an
// arbitrarily large body.
const MaxBatchBytes = 64 << 20

var (
	encOnce sync.Once
	enc     *zstd.Encoder
	decOnce sync.Once
	dec     *zstd.Decoder
)

func encoder() *zstd.Encoder {
	encOnce.Do(func() {
		// SpeedFastest: the sensor may be a 500 MHz mips core; the ratio
		// difference on JSON is small next to the CPU difference.
		enc, _ = zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedFastest), zstd.WithEncoderConcurrency(1))
	})
	return enc
}

func decoder() *zstd.Decoder {
	decOnce.Do(func() {
		dec, _ = zstd.NewReader(nil, zstd.WithDecoderMaxMemory(MaxBatchBytes), zstd.WithDecoderConcurrency(1))
	})
	return dec
}

// Encode writes events as newline-delimited JSON and compresses the result.
func Encode(events []Event) ([]byte, error) {
	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	for i := range events {
		if err := e.Encode(&events[i]); err != nil {
			return nil, fmt.Errorf("encode event %d: %w", events[i].Seq, err)
		}
	}
	return encoder().EncodeAll(buf.Bytes(), nil), nil
}

// Decode reverses Encode. It rejects input that inflates past MaxBatchBytes.
func Decode(body []byte) ([]Event, error) {
	raw, err := decoder().DecodeAll(body, nil)
	if err != nil {
		return nil, fmt.Errorf("decompress batch: %w", err)
	}
	if len(raw) > MaxBatchBytes {
		return nil, errors.New("batch too large")
	}
	return DecodeJSONL(bytes.NewReader(raw))
}

// DecodeJSONL reads uncompressed newline-delimited events.
func DecodeJSONL(r io.Reader) ([]Event, error) {
	var out []Event
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 8<<20)
	for line := 1; sc.Scan(); line++ {
		b := bytes.TrimSpace(sc.Bytes())
		if len(b) == 0 {
			continue
		}
		var ev Event
		if err := json.Unmarshal(b, &ev); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		out = append(out, ev)
	}
	return out, sc.Err()
}
