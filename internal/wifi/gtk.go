package wifi

import (
	"crypto/aes"
	"crypto/rc4" //nolint:gosec // WPA1/TKIP key data is RC4 by definition
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/xen0bit/netgraph/internal/wire"
)

// Group keys. An access point encrypts broadcast and multicast frames to its
// clients with a group temporal key (GTK), which it hands each client inside
// 4-way handshake message 3 and again in every group-key rekey, encrypted
// with that client's KEK. A sensor holding the client's PTK can unwrap it,
// and then decrypt the AP's group-addressed traffic: the mDNS, SSDP and DHCP
// broadcasts that name devices.

// errRelayed marks a group frame the access point relays from one of its
// own clients whose pairwise key is known: the sensor already decrypted that
// frame on its way up, so decoding the copy would count it twice.
var errRelayed = errors.New("wifi: group frame relays a known client")

// groupKey is one installed GTK.
type groupKey struct {
	tk   []byte    // 16 bytes for CCMP/GCMP-128, 32 for TKIP/GCMP-256
	tkip bool      // 32 bytes; a GCMP-256 group cipher in the beacon overrides it
	ts   time.Time // when the AP sent it: a later key in the slot wins
}

// GroupKeyRecord is a GTK as the AP sent it to one client, still wrapped
// with that client's KEK, with what is needed to re-derive the KEK from a
// PMK: the addresses, the SSID and the client's handshake nonces. It holds
// no usable key, so a sensor can ship it for others to unwrap themselves.
type GroupKeyRecord struct {
	BSSID, STA, SSID string
	KeyID            int
	ANonce, SNonce   []byte
	Descriptor       byte
	KeyInfo          uint16
	KeyLength        uint16
	IV               []byte
	KeyData          []byte // wrapped
	TS               time.Time
}

// maxWrappedKeyData bounds the key data taken from a stored record. An RSN
// message 3 carries the RSN IE and a GTK KDE: well under this.
const maxWrappedKeyData = 512

// apGroup is an access point's GTKs by key ID, and the network whose PMK
// led to them (so revoking that PMK drops them).
type apGroup struct {
	ssid string
	keys [4]*groupKey
}

// IV is the EAPOL-Key IV, which keys RC4 for WPA1/TKIP key data.
func (k *EAPOLKey) keyIV() []byte { return k.IV[:] }

// encryptedKeyData reports whether the key data is encrypted with the KEK:
// the RSN Encrypted Key Data bit, or a WPA1 group-key message (which always
// is).
func (k *EAPOLKey) encryptedKeyData() bool {
	if k.Descriptor == 254 {
		return !k.Pairwise() && len(k.KeyData) > 0
	}
	return k.KeyInfo&0x1000 != 0
}

// groupKeyIndex is the WPA1 key index carried in the key information.
func (k *EAPOLKey) groupKeyIndex() int { return int(k.KeyInfo>>4) & 0x3 }

// decryptKeyData unwraps the key data with the KEK: RC4 for descriptor
// version 1, AES key wrap (RFC 3394) for versions 2 and 3.
func (k *EAPOLKey) decryptKeyData(kek []byte) ([]byte, error) {
	if len(kek) != 16 {
		return nil, fmt.Errorf("eapol: KEK length %d", len(kek))
	}
	switch k.Version() {
	case 1:
		iv := k.keyIV()
		key := make([]byte, 0, 32)
		key = append(append(key, iv...), kek...)
		rc, err := rc4.NewCipher(key) //nolint:gosec // see import
		if err != nil {
			return nil, err
		}
		var skip [256]byte
		rc.XORKeyStream(skip[:], skip[:]) // RC4 key data discards 256 bytes
		out := make([]byte, len(k.KeyData))
		rc.XORKeyStream(out, k.KeyData)
		return out, nil
	case 2, 3:
		return aesUnwrap(kek, k.KeyData)
	}
	return nil, fmt.Errorf("eapol: key descriptor version %d", k.Version())
}

// aesUnwrap is the RFC 3394 AES key unwrap with the default IV.
func aesUnwrap(kek, c []byte) ([]byte, error) {
	if len(c)%8 != 0 || len(c) < 24 {
		return nil, fmt.Errorf("eapol: wrapped key data length %d", len(c))
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	n := len(c)/8 - 1
	var a [8]byte
	copy(a[:], c[:8])
	r := make([]byte, n*8)
	copy(r, c[8:])
	var b [16]byte
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			t := uint64(n*j + i)
			binary.BigEndian.PutUint64(b[:8], binary.BigEndian.Uint64(a[:])^t)
			copy(b[8:], r[(i-1)*8:i*8])
			block.Decrypt(b[:], b[:])
			copy(a[:], b[:8])
			copy(r[(i-1)*8:i*8], b[8:])
		}
	}
	if subtle.ConstantTimeCompare(a[:], []byte{0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6}) != 1 {
		return nil, fmt.Errorf("eapol: key data integrity check failed")
	}
	return r, nil
}

// aesWrap is aesUnwrap's inverse, for tests.
func aesWrap(kek, p []byte) ([]byte, error) {
	if len(p)%8 != 0 || len(p) < 16 {
		return nil, fmt.Errorf("aes wrap: length %d", len(p))
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	n := len(p) / 8
	a := uint64(0xa6a6a6a6a6a6a6a6)
	r := append([]byte(nil), p...)
	var b [16]byte
	for j := 0; j <= 5; j++ {
		for i := 1; i <= n; i++ {
			binary.BigEndian.PutUint64(b[:8], a)
			copy(b[8:], r[(i-1)*8:i*8])
			block.Encrypt(b[:], b[:])
			a = binary.BigEndian.Uint64(b[:8]) ^ uint64(n*j+i)
			copy(r[(i-1)*8:i*8], b[8:])
		}
	}
	return append(binary.BigEndian.AppendUint64(nil, a), r...), nil
}

// gtkKDE finds the GTK key data encapsulation in RSN key data: type 0xdd,
// OUI 00:0f:ac, data type 1, then the key ID, a reserved byte and the GTK.
// A 0xdd element of length zero starts the padding.
func gtkKDE(kd []byte) (int, []byte, bool) {
	for len(kd) >= 2 {
		id, n := kd[0], int(kd[1])
		if id == 0xdd && n == 0 {
			break // padding
		}
		if 2+n > len(kd) {
			break
		}
		el := kd[2 : 2+n]
		if id == 0xdd && n >= 6+2 && el[0] == 0x00 && el[1] == 0x0f && el[2] == 0xac && el[3] == 1 {
			return int(el[4] & 0x3), el[6:], true
		}
		kd = kd[2+n:]
	}
	return 0, nil, false
}

// installGTK takes the GTK out of a key message's decrypted key data and
// installs it for the access point, unless the slot already holds a key the
// AP sent later. It reports the key ID and whether the message carried one.
func (k *Keyring) installGTK(bssid, ssid string, msg *EAPOLKey, kek []byte, ts time.Time) (int, bool, error) {
	if !msg.encryptedKeyData() {
		return 0, false, nil
	}
	kd, err := msg.decryptKeyData(kek)
	if err != nil {
		return 0, false, err
	}
	var idx int
	var gtk []byte
	if msg.Descriptor == 254 {
		// WPA1: the key data is the bare GTK.
		idx, gtk = msg.groupKeyIndex(), kd
		if n := int(msg.KeyLength); n > 0 && n <= len(gtk) {
			gtk = gtk[:n]
		}
	} else {
		var ok bool
		if idx, gtk, ok = gtkKDE(kd); !ok {
			return 0, false, nil
		}
	}
	gk := groupKey{tk: append([]byte(nil), gtk...), ts: ts}
	switch len(gtk) {
	case 16:
	case 32:
		gk.tkip = true
	default:
		return 0, false, fmt.Errorf("eapol: GTK length %d", len(gtk))
	}
	key := strings.ToLower(bssid)
	k.mu.Lock()
	defer k.mu.Unlock()
	g := k.groups[key]
	if g == nil || g.ssid != strings.ToLower(ssid) {
		if len(k.groups) > 50_000 {
			clear(k.groups)
		}
		g = &apGroup{ssid: strings.ToLower(ssid)}
		k.groups[key] = g
	}
	if old := g.keys[idx]; old == nil || !old.ts.After(ts) {
		g.keys[idx] = &gk
	}
	return idx, true, nil
}

// record describes a GTK message for shipping: the wrapped key data and
// the inputs that re-derive the KEK that wraps it.
func record(ap, sta net.HardwareAddr, ssid string, keyID int, src pairSource, msg *EAPOLKey, ts time.Time) *GroupKeyRecord {
	return &GroupKeyRecord{
		BSSID: ap.String(), STA: sta.String(), SSID: ssid, KeyID: keyID,
		ANonce: append([]byte(nil), src.nonces[:32]...), SNonce: append([]byte(nil), src.nonces[32:]...),
		Descriptor: msg.Descriptor, KeyInfo: msg.KeyInfo, KeyLength: msg.KeyLength,
		IV: append([]byte(nil), msg.IV[:]...), KeyData: append([]byte(nil), msg.KeyData...), TS: ts,
	}
}

// GroupKeyFromWire decodes a group-key record from the server; ok is false
// for a malformed one.
func GroupKeyFromWire(g wire.WiFiGTK) (GroupKeyRecord, bool) {
	an, err1 := hex.DecodeString(g.ANonce)
	sn, err2 := hex.DecodeString(g.SNonce)
	iv, err3 := hex.DecodeString(g.IV)
	kd, err4 := hex.DecodeString(g.KeyData)
	if err := errors.Join(err1, err2, err3, err4); err != nil || g.Descriptor < 0 || g.Descriptor > 255 ||
		g.KeyInfo < 0 || g.KeyInfo > 0xffff || g.KeyLength < 0 || g.KeyLength > 0xffff {
		return GroupKeyRecord{}, false
	}
	return GroupKeyRecord{
		BSSID: g.BSSID, STA: g.STA, SSID: g.SSID, KeyID: g.KeyID, ANonce: an, SNonce: sn,
		Descriptor: byte(g.Descriptor), KeyInfo: uint16(g.KeyInfo), KeyLength: uint16(g.KeyLength),
		IV: iv, KeyData: kd, TS: g.TS,
	}, true
}

// Wire is the record as a wifi_gtk event carries it.
func (r *GroupKeyRecord) Wire() *wire.WiFiGTK {
	return &wire.WiFiGTK{
		BSSID: r.BSSID, STA: r.STA, SSID: r.SSID, KeyID: r.KeyID,
		ANonce: hex.EncodeToString(r.ANonce), SNonce: hex.EncodeToString(r.SNonce),
		Descriptor: int(r.Descriptor), KeyInfo: int(r.KeyInfo), KeyLength: int(r.KeyLength),
		IV: hex.EncodeToString(r.IV), KeyData: hex.EncodeToString(r.KeyData),
	}
}

// LoadGroupKey installs a GTK from a stored record (another sensor's, or
// this one's before a restart): it re-derives the client's PTK from the PMK
// for the record's SSID and the nonces, and unwraps the key data with its
// KEK. It returns false (no error) without a PMK for the SSID, and skips
// work when the slot already holds a key at least as recent.
func (k *Keyring) LoadGroupKey(r GroupKeyRecord) (bool, error) {
	if len(r.ANonce) != 32 || len(r.SNonce) != 32 || len(r.IV) != 16 || len(r.KeyData) > maxWrappedKeyData || r.KeyID < 0 || r.KeyID > 3 {
		return false, fmt.Errorf("wifi: malformed group key record")
	}
	ap, err := net.ParseMAC(r.BSSID)
	if err != nil {
		return false, err
	}
	sta, err := net.ParseMAC(r.STA)
	if err != nil {
		return false, err
	}
	if g := k.group(ap.String(), r.KeyID); g != nil && !g.ts.Before(r.TS) {
		return true, nil
	}
	pmk := k.pmkFor(r.SSID)
	if len(pmk) != 32 {
		return false, nil
	}
	msg := &EAPOLKey{Descriptor: r.Descriptor, KeyInfo: r.KeyInfo, KeyLength: r.KeyLength, KeyData: r.KeyData}
	copy(msg.IV[:], r.IV)
	ptk, err := DerivePTK(pmk, ap, sta, r.ANonce, r.SNonce, ptkBits)
	if err != nil {
		return false, err
	}
	_, ok, err := k.installGTK(ap.String(), r.SSID, msg, splitPTK(ptk, msg.Version() == 1).KEK, r.TS)
	return ok, err
}

// processGroupKey follows group-key handshake message 1, in which the AP
// sends a client the new GTK (a periodic rekey, or a client leaving).
// Holding that client's PTK is enough to verify and unwrap it.
func (k *Keyring) processGroupKey(f *Frame, msg *EAPOLKey, info HandshakeInfo) HandshakeInfo {
	info.Group = true
	ack, mic := msg.KeyInfo&0x0080 != 0, msg.KeyInfo&0x0100 != 0
	if !ack || !mic {
		info.Message = 2 // the client's acknowledgement
		return info
	}
	info.Message = 1
	if f.BSSID == nil || f.Dst == nil {
		return info
	}
	key := pairKey(f.BSSID, f.Dst)
	k.mu.RLock()
	ptk, src := k.pairs[key], k.pairNet[key]
	k.mu.RUnlock()
	if ptk == nil {
		return info
	}
	ok, err := msg.VerifyMIC(ptk.KCK)
	if err != nil || !ok {
		info.Err = err
		return info
	}
	info.Valid = true
	id, ok, err := k.installGTK(f.BSSID.String(), src.ssid, msg, ptk.KEK, f.TS)
	info.GTK, info.Err = ok, err
	if ok {
		info.GroupKey = record(f.BSSID, f.Dst, src.ssid, id, src, msg, f.TS)
	}
	return info
}

// group returns the GTK an access point uses under a key ID.
func (k *Keyring) group(bssid string, id int) *groupKey {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if g := k.groups[strings.ToLower(bssid)]; g != nil {
		return g.keys[id&3]
	}
	return nil
}

// GroupKeys returns the number of access points with an installed GTK.
func (k *Keyring) GroupKeys() int {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return len(k.groups)
}
