package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/xen0bit/netgraph/internal/capture"
	"github.com/xen0bit/netgraph/internal/sensor"
	"github.com/xen0bit/netgraph/internal/wire"
)

// check is the preflight a deployment needs: can we resolve the interface,
// open it with CAP_NET_RAW, is it the link type we think, and can we reach
// and authenticate to the server?
func check(args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	iface := fs.String("iface", envOr("NETGRAPH_IFACE", ""), "interface name, or an address/CIDR the interface holds; $NETGRAPH_IFACE")
	server := fs.String("server", envOr("NETGRAPH_SERVER", ""), "netgraph server URL; $NETGRAPH_SERVER")
	tokenFile := fs.String("token-file", "", "file holding the ingest token (default $NETGRAPH_TOKEN)")
	caFile := fs.String("ca-file", "", "PEM CA bundle to verify the server's certificate")
	insecure := fs.Bool("insecure-skip-verify", false, "do not verify the server's TLS certificate")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *iface == "" {
		return errors.New("-iface is required")
	}
	name, err := sensor.ResolveInterface(*iface)
	if err != nil {
		return err
	}
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return err
	}
	fmt.Printf("interface  %s\n", name)
	fmt.Printf("hardware   %s\n", ifc.HardwareAddr)
	addrs, _ := ifc.Addrs()
	for _, a := range addrs {
		fmt.Printf("address    %s\n", a)
	}
	// Opening the socket is the only reliable CAP_NET_RAW test; close it
	// immediately so a running sensor is not disturbed.
	src, err := capture.OpenLive(capture.LiveConfig{Interface: name, RingBytes: 1 << 20})
	if err != nil {
		return fmt.Errorf("open %s: %w", name, err)
	}
	link := src.LinkType()
	src.Close()
	fmt.Printf("link       %s\n", linkName(link))
	if capture.IsWiFi(link) {
		fmt.Println("wifi       monitor-mode link detected")
	}
	if *server == "" {
		fmt.Println("server     skipped (-server not set)")
		return nil
	}
	token, err := readToken(*tokenFile)
	if err != nil {
		return err
	}
	tlsCfg, err := tlsConfig(*caFile, *insecure)
	if err != nil {
		return err
	}
	base := strings.TrimRight(*server, "/")
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/healthz", nil)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("server health: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("server health: %s", resp.Status)
	}
	fmt.Printf("server     %s healthy\n", base)
	if token == "" {
		fmt.Println("token      none (server may reject ingest)")
		return nil
	}
	sh := wire.NewShipper(wire.ShipperConfig{URL: base, Token: token, Sensor: "check", TLSConfig: tlsCfg})
	keys, err := sh.FetchWiFiKeys(ctx)
	if err != nil {
		return fmt.Errorf("wifi key sync: %w", err)
	}
	fmt.Printf("wifi keys  %d networks, %d handshakes, %d group keys\n", len(keys.PMKs), len(keys.Handshakes), len(keys.GroupKeys))
	return nil
}
