// Package ech observes Encrypted Client Hello (ECH) in a TLS ClientHello.
// It is passive and never decrypts the inner hello: it reports that ECH was
// present, the outer SNI and the ECH config id, so a finding can say the name
// on the wire may not be the name the server actually serves.
package ech

import (
	"errors"

	"github.com/xen0bit/netgraph/internal/decode"
)

// ErrNoClientHello means the bytes are not a TLS ClientHello.
var ErrNoClientHello = errors.New("ech: no client hello")

// Observation is what the outer ClientHello exposes.
type Observation struct {
	OuterSNI   string   `json:"outer_sni,omitempty"`
	ALPN       []string `json:"alpn,omitempty"`
	JA4        string   `json:"ja4,omitempty"`
	ECH        bool     `json:"ech"`
	ECHType    uint8    `json:"ech_type,omitempty"`
	ConfigID   uint8    `json:"config_id,omitempty"`
	PayloadLen int      `json:"payload_len,omitempty"`
}

// Inspect parses TLS records from the start of a TCP stream. The bool is true
// only when ECH is present.
func Inspect(b []byte) (Observation, bool, error) {
	ch, err := decode.ParseTLSRecords(b)
	if err != nil {
		if errors.Is(err, decode.ErrNeedMore) || errors.Is(err, decode.ErrNotTLS) {
			return Observation{}, false, ErrNoClientHello
		}
		return Observation{}, false, err
	}
	o := Observation{
		OuterSNI: ch.SNI, ALPN: ch.ALPN, JA4: ch.JA4,
		ECH: ch.ECH, ECHType: ch.ECHType, ConfigID: ch.ECHConfigID, PayloadLen: ch.ECHPayloadLen,
	}
	return o, ch.ECH, nil
}
