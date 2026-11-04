package wifi_test

import (
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/capture"
	"github.com/xen0bit/netgraph/internal/wifi"
	"github.com/xen0bit/netgraph/internal/wire"
)

// These captures are real: hostapd and wpa_supplicant on mac80211_hwsim radios, joining and
// then pinging, heard by a third radio in monitor mode. The PMKs are what hostapd logged for
// those sessions, on a test network that no longer exists.
var labPMK = map[string]string{
	"lab-sae":    "16cc07cfddb6cca8346d300a5f2198c27fb3eabeb3a55ca6e92078c109732c25",
	"lab-owe":    "f29a29b9ce378234cb5428a1e013cfa8c32ed97f23e53b826c9e4ad969935ac6",
	"lab-psk256": "1973af8fe816dc0136faefcc14d43e167f3859d891b9abadcf2f3f68839da579",
}

type replayResult struct {
	valid, installed, gtk int
	mics                  int
	ping                  int
	wifiKeys              []wire.WiFiKey
	groupKeys             []wire.WiFiGTK
	failed                string
}

// replay feeds a capture through a processor, counting what came out.
func replay(t *testing.T, name string, keys *wifi.Keyring) replayResult {
	t.Helper()
	src, err := capture.OpenFile("testdata/" + name + ".pcap")
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	var r replayResult
	p := wifi.NewProcessor(wifi.Config{Keys: keys, Emit: func(ev wire.Event) {
		switch {
		case ev.WiFi != nil && ev.WiFi.EAPOL != nil:
			r.mics++
			if ev.WiFi.EAPOL.Valid {
				r.valid++
			}
			if ev.WiFi.EAPOL.Installed {
				r.installed++
			}
			if ev.WiFi.EAPOL.GTK {
				r.gtk++
			}
			if ev.WiFi.Error != "" {
				r.failed = ev.WiFi.Error
			}
		case ev.WiFiKey != nil:
			r.wifiKeys = append(r.wifiKeys, *ev.WiFiKey)
		case ev.WiFiGTK != nil:
			r.groupKeys = append(r.groupKeys, *ev.WiFiGTK)
		}
	}})
	p.SetData(func(_ time.Time, frame []byte) {
		// Ethernet: an IPv4 ICMP packet from one lab address to the other.
		if len(frame) >= 34 && frame[12] == 8 && frame[13] == 0 && frame[23] == 1 && frame[26] == 10 && frame[27] == 99 {
			r.ping++
		}
	})
	for {
		data, ts, err := src.ReadPacket()
		if errors.Is(err, io.EOF) {
			return r
		}
		if err != nil {
			t.Fatal(err)
		}
		p.Handle(ts, data, true)
	}
}

func keyringFor(t *testing.T, ssid string, pmks ...string) *wifi.Keyring {
	t.Helper()
	sec := &wifi.Secrets{}
	for _, h := range pmks {
		b, err := hex.DecodeString(h)
		if err != nil {
			t.Fatal(err)
		}
		sec.Add(ssid, b)
	}
	k := wifi.NewKeyring()
	k.SetSecrets(sec)
	return k
}

func TestRealHandshakesDecrypt(t *testing.T) {
	for name, pmk := range labPMK {
		t.Run(name, func(t *testing.T) {
			r := replay(t, name, keyringFor(t, name, pmk))
			if r.mics == 0 {
				t.Fatal("no handshake in the capture")
			}
			if r.failed != "" {
				t.Errorf("handshake error: %s", r.failed)
			}
			if r.valid < 3 || r.installed < 3 {
				t.Errorf("valid %d, installed %d of %d messages", r.valid, r.installed, r.mics)
			}
			if r.ping < 8 {
				t.Errorf("decrypted %d lab pings, sent 4 and replied to", r.ping)
			}
			if r.gtk == 0 {
				t.Error("no group key from message 3")
			}
		})
	}
}

// Without the session's PMK nothing decrypts, and a wrong one is never claimed to work. For
// SAE the passphrase is no help: that's the forward secrecy, not a gap here.
func TestRealHandshakesNeedTheRightPMK(t *testing.T) {
	wrong := strings.Repeat("ab", 32)
	for name := range labPMK {
		t.Run(name, func(t *testing.T) {
			none := replay(t, name, wifi.NewKeyring())
			if none.valid != 0 || none.installed != 0 || none.ping != 0 {
				t.Errorf("with no key: %+v", none)
			}
			bad := replay(t, name, keyringFor(t, name, wrong))
			if bad.valid != 0 || bad.installed != 0 || bad.ping != 0 || len(bad.wifiKeys) != 0 {
				t.Errorf("with a wrong key: %+v", bad)
			}
		})
	}
	pass, err := wifi.PMK("netgraph-test-password", "lab-sae")
	if err != nil {
		t.Fatal(err)
	}
	if r := replay(t, "lab-sae", keyringFor(t, "lab-sae", hex.EncodeToString(pass))); r.installed != 0 || r.ping != 0 {
		t.Errorf("SAE fell to its passphrase: %+v", r)
	}
}

// An SAE PMK is per association, so a network holds several, and the MIC picks.
func TestRightPMKAmongSeveral(t *testing.T) {
	decoys := []string{strings.Repeat("01", 32), strings.Repeat("02", 32)}
	for _, order := range [][]string{
		{decoys[0], decoys[1], labPMK["lab-sae"]},
		{labPMK["lab-sae"], decoys[0], decoys[1]},
		{decoys[0], labPMK["lab-sae"], decoys[1]},
	} {
		if r := replay(t, "lab-sae", keyringFor(t, "lab-sae", order...)); r.ping < 8 || r.installed < 3 {
			t.Errorf("%v: %+v", order, r)
		}
	}
}

// A sensor that missed the handshake gets the public parts from the server, and rebuilds
// the keys from its own PMK. Replaying only what follows the handshake shows they work.
func TestStoredHandshakeRederives(t *testing.T) {
	for name, pmk := range labPMK {
		t.Run(name, func(t *testing.T) {
			r := replay(t, name, keyringFor(t, name, pmk))
			if len(r.wifiKeys) == 0 {
				t.Fatal("no handshake record")
			}
			if name != "lab-psk256" && len(r.groupKeys) == 0 {
				t.Fatal("no group key record")
			}
			rec := r.wifiKeys[len(r.wifiKeys)-1]
			if rec.Cipher != "CCMP" {
				t.Errorf("recorded cipher %q: re-deriving needs the station's choice", rec.Cipher)
			}
			fresh := keyringFor(t, name, pmk)
			an, _ := hex.DecodeString(rec.ANonce)
			sn, _ := hex.DecodeString(rec.SNonce)
			ok, err := fresh.LoadHandshakeCipher(rec.BSSID, rec.STA, rec.SSID, an, sn, rec.KeyVersion, rec.Cipher)
			if err != nil || !ok {
				t.Fatalf("%v %v", ok, err)
			}
			if got := replayData(t, name, fresh); got < 8 {
				t.Errorf("decrypted %d with re-derived keys", got)
			}
			// With several PMKs and no MIC to choose by, it says it can't rather than guess.
			many := keyringFor(t, name, strings.Repeat("03", 32), pmk)
			if ok, err := many.LoadHandshakeCipher(rec.BSSID, rec.STA, rec.SSID, an, sn, rec.KeyVersion, rec.Cipher); ok || err != nil {
				t.Errorf("%v %v", ok, err)
			}
			for _, g := range r.groupKeys {
				rec, ok := wifi.GroupKeyFromWire(g)
				if !ok {
					t.Fatalf("%+v", g)
				}
				// Unwrapping is self-checking, so this works among several.
				if ok, err := many.LoadGroupKey(rec); !ok || err != nil {
					t.Errorf("group key among several: %v %v", ok, err)
				}
			}
		})
	}
}

// replayData counts pings, leaving EAPOL out so only already-loaded keys can decrypt.
func replayData(t *testing.T, name string, keys *wifi.Keyring) int {
	t.Helper()
	src, err := capture.OpenFile("testdata/" + name + ".pcap")
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	pings := 0
	p := wifi.NewProcessor(wifi.Config{Keys: keys})
	p.SetData(func(_ time.Time, frame []byte) {
		if len(frame) >= 34 && frame[12] == 8 && frame[13] == 0 && frame[23] == 1 && frame[26] == 10 && frame[27] == 99 {
			pings++
		}
	})
	for {
		data, ts, err := src.ReadPacket()
		if errors.Is(err, io.EOF) {
			return pings
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, raw, err := wifi.ParseRadiotap(data); err == nil {
			if f, err := wifi.Parse(raw); err == nil && !f.Protected {
				if etype, _, err := f.LLC(); err == nil && etype == 0x888e {
					continue
				}
			}
		}
		p.Handle(ts, data, true)
	}
}

func TestSecretsAddKeepsNewestFirst(t *testing.T) {
	a, b, c := []byte(strings.Repeat("a", 32)), []byte(strings.Repeat("b", 32)), []byte(strings.Repeat("c", 32))
	s := &wifi.Secrets{}
	s.Add("Net", a)
	s.Add("net", b)
	s.Add("NET", c)
	s.Add("net", b) // saying it again makes it newest, and doesn't repeat it
	if string(s.PMKs["net"]) != string(b) || len(s.More["net"]) != 2 {
		t.Errorf("%+v", s)
	}
	var all []string
	s.All(func(_ string, p []byte) { all = append(all, string(p[:1])) })
	if strings.Join(all, "") != "acb" {
		t.Errorf("%v", all)
	}
	var rebuilt wifi.Secrets
	s.All(func(ssid string, p []byte) { rebuilt.Add(ssid, p) })
	if string(rebuilt.PMKs["net"]) != string(b) || len(rebuilt.More["net"]) != 2 {
		t.Errorf("%+v", rebuilt)
	}
	for i := range 100 {
		s.Add("net", []byte(strings.Repeat(string(rune('0'+i%10))+string(rune('0'+i/10)), 16)))
	}
	if n := len(s.More["net"]) + 1; n > 64 {
		t.Errorf("%d PMKs", n)
	}
}
