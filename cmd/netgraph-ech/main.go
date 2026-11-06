//go:build experimental

// Command netgraph-ech is an experimental, opt-in ECH observer. It reads a
// pcap file or a live Linux interface and reports TLS ClientHellos that carry
// the encrypted_client_hello extension. It never decrypts the inner hello and
// is built only with -tags experimental.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/xen0bit/netgraph/internal/capture"
	"github.com/xen0bit/netgraph/internal/ech"
)

type result struct {
	TS   int64           `json:"ts"`
	Src  string          `json:"src,omitempty"`
	Dst  string          `json:"dst,omitempty"`
	Link int             `json:"link"`
	Obs  ech.Observation `json:"observation"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "netgraph-ech:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("netgraph-ech", flag.ContinueOnError)
	pcap := fs.String("pcap", "", "pcap/pcapng file")
	iface := fs.String("iface", "", "live Linux interface (needs CAP_NET_RAW)")
	limit := fs.Int("limit", 0, "stop after this many ECH hellos (0: no limit)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if (*pcap == "") == (*iface == "") {
		return errors.New("give exactly one of -pcap or -iface")
	}
	var src capture.Source
	var err error
	if *pcap != "" {
		src, err = capture.OpenFile(*pcap)
	} else {
		src, err = capture.OpenLive(capture.LiveConfig{Interface: *iface})
	}
	if err != nil {
		return err
	}
	defer src.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	enc := json.NewEncoder(os.Stdout)
	n := 0
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		data, ts, err := src.ReadPacket()
		if err != nil {
			if errors.Is(err, capture.ErrTimeout) {
				continue
			}
			return err
		}
		if r, ok := inspectFrame(data, src.LinkType(), ts); ok {
			if err := enc.Encode(r); err != nil {
				return err
			}
			n++
			if *limit > 0 && n >= *limit {
				return nil
			}
		}
	}
}

func inspectFrame(data []byte, link int, ts time.Time) (result, bool) {
	dec := decoder(link)
	if dec == nil {
		return result{}, false
	}
	p := gopacket.NewPacket(data, dec, gopacket.Default)
	tcp, ok := p.TransportLayer().(*layers.TCP)
	if !ok || len(tcp.Payload) == 0 {
		return result{}, false
	}
	obs, yes, err := ech.Inspect(tcp.Payload)
	if err != nil || !yes {
		return result{}, false
	}
	r := result{TS: ts.UnixMilli(), Link: link, Obs: obs}
	if ip := p.NetworkLayer(); ip != nil {
		r.Src, r.Dst = ip.NetworkFlow().Src().String(), ip.NetworkFlow().Dst().String()
	}
	return r, true
}

func decoder(link int) gopacket.Decoder {
	switch link {
	case capture.LinkEthernet:
		return layers.LayerTypeEthernet
	case capture.LinkRaw, capture.LinkIPv4:
		return layers.LayerTypeIPv4
	case capture.LinkIPv6:
		return layers.LayerTypeIPv6
	case capture.LinkSLL:
		return layers.LayerTypeLinuxSLL
	}
	return nil
}
