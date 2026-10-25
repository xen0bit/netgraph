// Command labapp generates the lab's traffic with real protocol stacks:
//
//	labapp web                  HTTPS on :443 (TLS, any *.lab.test name), HTTP/3 on
//	                            udp/443, HTTP on :80; /hold?secs=N streams for N seconds
//	labapp h3get URL            one HTTP/3 GET (quic-go), insecure
//	labapp ssdp NAME            announce a UPnP device every 5s, like a smart TV
//
// It lives in its own module so quic-go never becomes a dependency of
// netgraph itself.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/quic-go/quic-go/http3"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: labapp web | h3get URL | ssdp NAME")
	}
	switch os.Args[1] {
	case "web":
		web()
	case "h3get":
		h3get(os.Args[2])
	case "ssdp":
		ssdp(os.Args[2])
	default:
		log.Fatalf("unknown command %q", os.Args[1])
	}
}

func cert() tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "lab.test"},
		DNSNames:     []string{"*.lab.test", "lab.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/hold", func(w http.ResponseWriter, r *http.Request) {
		secs, _ := strconv.Atoi(r.URL.Query().Get("secs"))
		chunk := make([]byte, 1000)
		fl, _ := w.(http.Flusher)
		for i := 0; i < secs; i++ {
			if _, err := w.Write(chunk); err != nil {
				return
			}
			if fl != nil {
				fl.Flush()
			}
			select {
			case <-r.Context().Done():
				return
			case <-time.After(time.Second):
			}
		}
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello from %s over %s\n", r.Host, r.Proto)
	})
	return mux
}

func web() {
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert()}, NextProtos: []string{"h2", "http/1.1"}}
	h := handler()
	go func() {
		srv := &http3.Server{Addr: ":443", Handler: h, TLSConfig: http3.ConfigureTLSConfig(&tls.Config{Certificates: tlsCfg.Certificates})}
		log.Fatal(srv.ListenAndServe())
	}()
	go func() {
		log.Fatal(http.ListenAndServe(":80", h))
	}()
	ln, err := tls.Listen("tcp", ":443", tlsCfg)
	if err != nil {
		log.Fatal(err)
	}
	log.Print("serving https, h3 and http")
	log.Fatal(http.Serve(ln, h))
}

func h3get(u string) {
	tr := &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // lab
	defer tr.Close()
	c := &http.Client{Transport: tr, Timeout: 20 * time.Second}
	resp, err := c.Get(u)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	fmt.Printf("%s %s", resp.Proto, b)
}

func ssdp(name string) {
	dst, _ := net.ResolveUDPAddr("udp4", "239.255.255.250:1900")
	conn, err := net.DialUDP("udp4", nil, dst)
	if err != nil {
		log.Fatal(err)
	}
	ip := conn.LocalAddr().(*net.UDPAddr).IP
	msg := fmt.Sprintf("NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nCACHE-CONTROL: max-age=1800\r\n"+
		"LOCATION: http://%s:8008/ssdp/device-desc.xml\r\nNT: urn:dial-multiscreen-org:service:dial:1\r\nNTS: ssdp:alive\r\n"+
		"SERVER: Linux/5.10 UPnP/1.0 %s\r\nUSN: uuid:lab-tv-0001::urn:dial-multiscreen-org:service:dial:1\r\n\r\n", ip, name)
	ctx := context.Background()
	for {
		if _, err := conn.Write([]byte(msg)); err != nil {
			log.Print(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}
