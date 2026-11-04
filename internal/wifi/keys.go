package wifi

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// Key derivation for WPA/WPA2-PSK. WPA3/SAE, OWE and 802.1X establish their PMK
// in ways a passive observer cannot reproduce; Keyring accepts a PMK for
// those cases, which is enough to follow the 4-way handshake. An SAE or OWE PMK
// changes with each association, so a network can have several: the handshake's
// MIC says which one, if any, belongs to it.

var errUnsupportedKey = errors.New("wifi: key exchange cannot be followed passively")

// PMK derives the 256-bit pairwise master key from a passphrase and SSID,
// or decodes a raw 64-hex-digit PSK.
func PMK(passphrase, ssid string) ([]byte, error) {
	if len(passphrase) == 64 {
		if b, err := hex.DecodeString(passphrase); err == nil {
			return b, nil
		}
	}
	if len(passphrase) < 8 || len(passphrase) > 63 {
		return nil, fmt.Errorf("wifi: passphrase must be 8..63 characters or 64 hex digits")
	}
	return pbkdf2SHA1([]byte(passphrase), []byte(ssid), 4096, 32), nil
}

// pbkdf2SHA1 is PBKDF2-HMAC-SHA1 (RFC 2898) with one block, enough for WPA.
func pbkdf2SHA1(password, salt []byte, iter, keyLen int) []byte {
	out := make([]byte, 0, keyLen)
	var block uint32 = 1
	for len(out) < keyLen {
		mac := hmac.New(sha1.New, password)
		mac.Write(salt)
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], block)
		mac.Write(b[:])
		u := mac.Sum(nil)
		t := append([]byte(nil), u...)
		for i := 1; i < iter; i++ {
			mac = hmac.New(sha1.New, password)
			mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
		block++
	}
	return out[:keyLen]
}

// PRF is the 802.11i pseudorandom function (HMAC-SHA1). Each block is
// HMAC-SHA1(key, label || 0x00 || data || counter) where the single-octet
// counter starts at 0, as in wpa_supplicant's sha1_prf. (Starting it at 1
// still round-trips against itself but never matches a real AP.)
func PRF(key []byte, label string, data []byte, n int) []byte {
	out := make([]byte, 0, n)
	for i := 0; len(out) < n; i++ {
		mac := hmac.New(sha1.New, key)
		mac.Write([]byte(label))
		mac.Write([]byte{0})
		mac.Write(data)
		mac.Write([]byte{byte(i)})
		out = append(out, mac.Sum(nil)...)
	}
	return out[:n]
}

// DerivePTK derives the pairwise transient key. bits is 384 for CCMP or 512
// for TKIP; aa and spa are the authenticator and supplicant addresses, and
// the nonces are 32 bytes each.
func DerivePTK(pmk, aa, spa, anonce, snonce []byte, bits int) ([]byte, error) {
	if len(pmk) != 32 || len(anonce) != 32 || len(snonce) != 32 || len(aa) != 6 || len(spa) != 6 {
		return nil, fmt.Errorf("wifi: bad PTK inputs")
	}
	if bits != 384 && bits != 512 {
		return nil, fmt.Errorf("wifi: unsupported PTK length %d", bits)
	}
	data := make([]byte, 0, 76)
	a, s := lessFirst(aa, spa)
	data = append(data, a...)
	data = append(data, s...)
	a, s = lessFirst(anonce, snonce)
	data = append(data, a...)
	data = append(data, s...)
	return PRF(pmk, "Pairwise key expansion", data, bits/8), nil
}

// kdfSHA256 is the 802.11 KDF over HMAC-SHA-256 (IEEE 802.11-2020 12.7.1.6.2). The output's
// length goes into every block, so a key of a different length differs throughout.
func kdfSHA256(key []byte, label string, context []byte, bits int) []byte {
	out := make([]byte, 0, (bits+7)/8+sha256.Size)
	for i := uint16(1); len(out) < (bits+7)/8; i++ {
		h := hmac.New(sha256.New, key)
		var n [2]byte
		binary.LittleEndian.PutUint16(n[:], i)
		h.Write(n[:])
		h.Write([]byte(label))
		h.Write(context)
		binary.LittleEndian.PutUint16(n[:], uint16(bits))
		h.Write(n[:])
		out = h.Sum(out)
	}
	return out[:(bits+7)/8]
}

func ptkContext(aa, spa, anonce, snonce []byte) []byte {
	data := make([]byte, 0, 76)
	a, s := lessFirst(aa, spa)
	data = append(append(data, a...), s...)
	a, s = lessFirst(anonce, snonce)
	return append(append(data, a...), s...)
}

// usesSHA256KDF says a handshake's key descriptor version means the SHA-256 KDF: version 3
// is the PSK-SHA256 and 802.1X-SHA256 suites, and version 0 leaves it to the AKM, of which
// SAE and OWE with group 19 are the ones supported here.
func usesSHA256KDF(version int) bool { return version == 0 || version == 3 }

// temporalBits is the length of a cipher's temporal key.
func temporalBits(cipher string) int {
	if cipher == "GCMP-256" || cipher == "CCMP-256" {
		return 256
	}
	return 128
}

// derivePair derives a client's keys for a handshake of this version and cipher. The two
// KDFs differ: PRF-SHA1 gives a prefix of one long stream, so a single length serves all
// ciphers, but the SHA-256 KDF's length changes the result.
func derivePair(pmk, aa, spa, anonce, snonce []byte, version int, cipher string) (*PTK, error) {
	if !usesSHA256KDF(version) {
		ptk, err := DerivePTK(pmk, aa, spa, anonce, snonce, ptkBits)
		if err != nil {
			return nil, err
		}
		p := splitPTK(ptk, version == 1)
		p.Cipher = cipher
		return p, nil
	}
	if len(pmk) != 32 || len(anonce) != 32 || len(snonce) != 32 || len(aa) != 6 || len(spa) != 6 {
		return nil, fmt.Errorf("wifi: bad PTK inputs")
	}
	tk := temporalBits(cipher)
	ptk := kdfSHA256(pmk, "Pairwise key expansion", ptkContext(aa, spa, anonce, snonce), 256+tk)
	p := &PTK{KCK: ptk[0:16], KEK: ptk[16:32], Cipher: cipher}
	if tk == 256 {
		p.TK256 = ptk[32:64]
		p.TK = ptk[32:48]
	} else {
		p.TK = ptk[32:48]
	}
	return p, nil
}

func lessFirst(a, b []byte) ([]byte, []byte) {
	if bytes.Compare(a, b) <= 0 {
		return a, b
	}
	return b, a
}

// PTK is the pairwise transient key split into its parts.
type PTK struct {
	KCK  []byte
	KEK  []byte
	TK   []byte // 16 bytes for CCMP and GCMP-128, 32 for TKIP
	TKIP bool
	// TK256 is the 32-byte temporal key GCMP-256 needs, when the PTK was
	// derived long enough. PRF output is a prefix of the longer output,
	// so deriving 512 bits leaves KCK, KEK and the 16-byte TK unchanged.
	TK256 []byte
	// Cipher is the pairwise cipher the station chose in message 2, or
	// empty when that message was not seen (the beacon decides then).
	Cipher string
}

// ptkBits is the PTK length to derive: always 512, so a GCMP-256 key is
// available whichever cipher the network turns out to use.
const ptkBits = 512

func splitPTK(ptk []byte, tkip bool) *PTK {
	p := &PTK{KCK: ptk[0:16], KEK: ptk[16:32], TK: ptk[32:], TKIP: tkip}
	if !tkip && len(ptk) >= 64 {
		p.TK, p.TK256 = ptk[32:48], ptk[32:64]
	}
	return p
}

// pairwiseCipher picks the cipher for a station's unicast frames: what it
// chose in its handshake, else the one GCMP suite an AP offers without
// CCMP. Empty means CCMP (or TKIP, which the PTK records itself).
func pairwiseCipher(chosen string, sec Security) string {
	if chosen != "" {
		return chosen
	}
	for _, c := range sec.Pairwise {
		if c == "CCMP-256" || c == "GCMP-128" || c == "GCMP-256" {
			return c
		}
	}
	if sec.UsesCCMP() || sec.UsesTKIP() {
		return ""
	}
	return ""
}

// rsnChoice returns the pairwise cipher and AKM named by the RSN element in an
// EAPOL-Key message's (unencrypted) key data: message 2 carries the
// station's choice there.
func rsnChoice(keyData []byte) (cipher, akm string) {
	ies, err := parseIEs(keyData)
	if err != nil {
		return "", ""
	}
	body, ok := ies.find(ieRSN)
	if !ok {
		return "", ""
	}
	s, err := parseSuiteIE(body, true)
	if err != nil {
		return "", ""
	}
	if len(s.Pairwise) == 1 {
		cipher = s.Pairwise[0]
	}
	if len(s.AKMs) == 1 {
		akm = s.AKMs[0]
	}
	return cipher, akm
}

// EAPOLKey is one 802.1X EAPOL-Key message. Raw aliases the frame and is
// needed to verify the MIC.
type EAPOLKey struct {
	Descriptor byte
	KeyInfo    uint16
	KeyLength  uint16
	Replay     uint64
	Nonce      [32]byte
	IV         [16]byte
	MIC        [16]byte
	KeyData    []byte
	Raw        []byte
	// AKM is what message 2 chose, when known. Version 0 leaves the MIC to it.
	AKM string
}

// Message is 1..4 for the 4-way handshake, 0 for a group-key message.
func (k *EAPOLKey) Message() int {
	ack := k.KeyInfo&0x0080 != 0
	mic := k.KeyInfo&0x0100 != 0
	secure := k.KeyInfo&0x0200 != 0
	switch {
	case ack && !mic && !secure:
		return 1
	case !ack && mic && !secure:
		return 2
	case ack && mic && secure:
		return 3
	case !ack && mic && secure:
		return 4
	}
	return 0
}

// Version is the key descriptor version: 1 TKIP/HMAC-MD5, 2 CCMP/HMAC-SHA1,
// 3 AES-CMAC.
func (k *EAPOLKey) Version() int { return int(k.KeyInfo & 0x7) }

func (k *EAPOLKey) Pairwise() bool { return k.KeyInfo&0x0008 != 0 }
func (k *EAPOLKey) Request() bool  { return k.KeyInfo&0x0800 != 0 }
func (k *EAPOLKey) Error() bool    { return k.KeyInfo&0x0400 != 0 }

// Cipher names the pairwise cipher implied by the descriptor version.
func (k *EAPOLKey) Cipher() string {
	switch k.Version() {
	case 1:
		return "TKIP"
	case 2:
		return "CCMP"
	case 0, 3:
		return "AES-CMAC"
	}
	return ""
}

// VerifyMIC checks the EAPOL-Key MIC with the key confirmation key: HMAC-MD5,
// HMAC-SHA1 or AES-CMAC. Version 0 leaves the choice to the AKM: SAE uses AES-CMAC, and
// OWE with group 19 uses HMAC-SHA-256 cut to 128 bits. The suites with longer MICs don't
// parse to this shape, so they fail here rather than verify.
func (k *EAPOLKey) VerifyMIC(kck []byte) (bool, error) {
	if len(k.Raw) < 99 {
		return false, fmt.Errorf("eapol: short key frame")
	}
	raw := append([]byte(nil), k.Raw...)
	// The MIC is at body offset 77; with the 4-byte 802.1X header that is
	// offset 81 in the frame. It is computed over the whole EAPOL-Key frame
	// — the 802.1X header included — with the MIC field zeroed, exactly as
	// hostapd/wpa_supplicant do. (Computing it over the descriptor alone
	// passes a self-consistent test but fails against every real AP.)
	for i := 81; i < 97; i++ {
		raw[i] = 0
	}
	body := raw
	var mac []byte
	switch k.Version() {
	case 1:
		h := hmac.New(md5.New, kck)
		h.Write(body)
		mac = h.Sum(nil)
	case 2:
		h := hmac.New(sha1.New, kck)
		h.Write(body)
		mac = h.Sum(nil)
	case 0, 3:
		if k.Version() == 0 && k.AKM == "OWE" {
			h := hmac.New(sha256.New, kck)
			h.Write(body)
			mac = h.Sum(nil)
			break
		}
		cm := aesCMAC(kck, body)
		mac = cm[:]
	default:
		return false, errUnsupportedKey
	}
	return subtle.ConstantTimeCompare(mac[:16], k.MIC[:]) == 1, nil
}

// ParseEAPOL decodes an EAPOL-Key frame (EtherType 0x888e).
func ParseEAPOL(b []byte) (*EAPOLKey, error) {
	if len(b) < 4+95 || b[1] != 3 {
		return nil, fmt.Errorf("eapol: not a key frame")
	}
	n := int(binary.BigEndian.Uint16(b[2:]))
	if n > len(b)-4 {
		return nil, fmt.Errorf("eapol: body overruns frame")
	}
	body := b[4 : 4+n]
	k := &EAPOLKey{Raw: b[:4+n], Descriptor: body[0]}
	k.KeyInfo = binary.BigEndian.Uint16(body[1:])
	k.KeyLength = binary.BigEndian.Uint16(body[3:])
	k.Replay = binary.BigEndian.Uint64(body[5:])
	copy(k.Nonce[:], body[13:45])
	copy(k.IV[:], body[45:61])
	copy(k.MIC[:], body[77:93])
	kd := int(binary.BigEndian.Uint16(body[93:95]))
	if 95+kd > len(body) {
		return nil, fmt.Errorf("eapol: key data overruns frame")
	}
	k.KeyData = body[95 : 95+kd]
	return k, nil
}

// HandshakeInfo is what the processor reports about an EAPOL-Key message.
// When Installed, it also carries the public inputs (nonces, addresses, SSID)
// the server needs to let another sensor re-derive the same key later.
type HandshakeInfo struct {
	Message   int
	Version   int
	Cipher    string
	Valid     bool
	Installed bool
	// Chosen is the pairwise cipher the station picked, if its message 2 was seen.
	Chosen string
	// Group marks a group-key handshake message (a GTK rekey) rather
	// than a 4-way handshake message; GTK that a group key was learned.
	Group, GTK bool
	// GroupKey, when a GTK was installed, is the message's wrapped key
	// data and KEK inputs, for the server to share with other sensors.
	GroupKey *GroupKeyRecord
	Err      error

	SSID           string
	AP, STA        string
	ANonce, SNonce []byte
}

type handshake struct {
	anonce, snonce []byte
	cipher         string // pairwise cipher from message 2's RSN element
	akm            string // and the AKM
}

// pairSource is what a PTK was derived from: the network whose PMK was
// used and the handshake's nonces. It lets a resync skip handshakes whose
// key is already installed.
type pairSource struct {
	ssid   string
	nonces [64]byte
}

func newPairSource(ssid string, anonce, snonce []byte) pairSource {
	s := pairSource{ssid: strings.ToLower(ssid)}
	copy(s.nonces[:32], anonce)
	copy(s.nonces[32:], snonce)
	return s
}

type network struct {
	ssid     string
	security Security
}

// Keyring holds what a passive observer knows: network names and security,
// WEP keys, WPA PMKs, and PTKs learned from 4-way handshakes. It lives only
// in memory; the sensor gets its PMKs and WEP keys from the server.
type Keyring struct {
	mu sync.RWMutex

	networks   map[string]network
	pmks       map[string][][]byte   // SSID -> its PMKs, the newest first
	pairs      map[string]*PTK       // "bssid|sta" -> PTK
	pairNet    map[string]pairSource // "bssid|sta" -> what derived the PTK
	pairPMK    map[string][]byte     // "bssid|sta" -> the PMK it came from
	handshakes map[string]*handshake
	groups     map[string]*apGroup // BSSID -> GTKs
	wep        [4][]byte
}

// Secrets are the operator's Wi-Fi keys: a PMK per network and up to four
// WEP keys. The server reads them from its key file and serves them to
// sensors, which hold them only in memory (Keyring.SetSecrets).
type Secrets struct {
	PMKs map[string][]byte // lower-case SSID -> 32-byte PMK, the newest given
	// More holds a network's earlier PMKs, where it has several: SAE and OWE have one per
	// association, so a handshake's MIC says which applies.
	More map[string][][]byte
	WEP  [4][]byte
}

// maxPMKsPerNetwork bounds how many PMKs one handshake gets tried against.
const maxPMKsPerNetwork = 64

// Add gives a network another PMK. The newest counts as its main one.
func (s *Secrets) Add(ssid string, pmk []byte) {
	ssid = strings.ToLower(ssid)
	if s.PMKs == nil {
		s.PMKs = map[string][]byte{}
	}
	old := s.PMKs[ssid]
	if bytes.Equal(old, pmk) {
		return
	}
	s.PMKs[ssid] = pmk
	if old == nil {
		return
	}
	if s.More == nil {
		s.More = map[string][][]byte{}
	}
	kept := slices.DeleteFunc(s.More[ssid], func(b []byte) bool { return bytes.Equal(b, pmk) || bytes.Equal(b, old) })
	kept = append(kept, old)
	if len(kept) >= maxPMKsPerNetwork {
		kept = kept[len(kept)-maxPMKsPerNetwork+1:]
	}
	s.More[ssid] = kept
}

// All lists every network's PMKs, a network's oldest first, so giving them to Add in this
// order rebuilds the same thing.
func (s *Secrets) All(yield func(ssid string, pmk []byte)) {
	for ssid, pmk := range s.PMKs {
		for _, old := range s.More[ssid] {
			yield(ssid, old)
		}
		yield(ssid, pmk)
	}
}

// LoadKeyFile reads Wi-Fi keys from a file. Each non-comment line is one of:
//
//	wpa2 <ssid> <passphrase or 64 hex digits>
//	pmk  <ssid> <64 hex digits>  (may repeat: SAE and OWE have one per association)
//	wep  <0-3>  <5, 13 or 16 bytes of hex>
//
// The format is deliberately separate from command-line flags so a
// passphrase does not appear in `ps` or a shell history. Passphrases are
// turned into PMKs here and not kept.
func LoadKeyFile(path string) (*Secrets, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseKeyFile(f)
}

// ParseKeyFile parses the key-file format documented on LoadKeyFile.
func ParseKeyFile(r io.Reader) (*Secrets, error) {
	s := &Secrets{PMKs: map[string][]byte{}}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 64*1024)
	line := 0
	for sc.Scan() {
		line++
		t := strings.TrimSpace(sc.Text())
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		kind, rest, _ := strings.Cut(t, " ")
		rest = strings.TrimSpace(rest)
		switch strings.ToLower(kind) {
		case "wpa", "wpa2":
			ssid, pass, ok := strings.Cut(rest, " ")
			if !ok || ssid == "" || strings.TrimSpace(pass) == "" {
				return nil, fmt.Errorf("line %d: expected <%s ssid passphrase>", line, kind)
			}
			pmk, err := PMK(strings.TrimSpace(pass), ssid)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", line, err)
			}
			s.Add(ssid, pmk)
		case "pmk":
			ssid, pmk, ok := strings.Cut(rest, " ")
			if !ok || ssid == "" {
				return nil, fmt.Errorf("line %d: expected <pmk ssid hex>", line)
			}
			b, err := hex.DecodeString(strings.TrimSpace(pmk))
			if err != nil || len(b) != 32 {
				return nil, fmt.Errorf("line %d: PMK must be 64 hex digits", line)
			}
			s.Add(ssid, b)
		case "wep":
			idx, hexKey, ok := strings.Cut(rest, " ")
			if !ok {
				return nil, fmt.Errorf("line %d: expected <wep index hex>", line)
			}
			n, err := strconv.Atoi(strings.TrimSpace(idx))
			if err != nil {
				return nil, fmt.Errorf("line %d: WEP index: %w", line, err)
			}
			b, err := ParseWEPKey(n, hexKey)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", line, err)
			}
			s.WEP[n] = b
		default:
			return nil, fmt.Errorf("line %d: unknown key kind %q", line, kind)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return s, nil
}

// ParseWEPKey validates a WEP key index (0..3) and decodes its hex.
func ParseWEPKey(index int, hexKey string) ([]byte, error) {
	if index < 0 || index > 3 {
		return nil, fmt.Errorf("wifi: WEP key index %d", index)
	}
	b, err := hex.DecodeString(strings.TrimSpace(hexKey))
	if err != nil || len(b) != 5 && len(b) != 13 && len(b) != 16 {
		return nil, fmt.Errorf("wifi: WEP key must be 5, 13 or 16 bytes of hex")
	}
	return b, nil
}

// NewKeyring returns an empty Keyring.
func NewKeyring() *Keyring {
	return &Keyring{
		networks:   map[string]network{},
		pmks:       map[string][][]byte{},
		pairPMK:    map[string][]byte{},
		pairs:      map[string]*PTK{},
		pairNet:    map[string]pairSource{},
		handshakes: map[string]*handshake{},
		groups:     map[string]*apGroup{},
	}
}

// SetSecrets replaces the PMKs and WEP keys. A pairwise key derived from a
// PMK that was removed or changed is dropped with it, so revoking a
// network's key on the server stops its decryption on the next sync.
func (k *Keyring) SetSecrets(s *Secrets) {
	pmks := map[string][][]byte{}
	var wep [4][]byte
	if s != nil {
		for ssid, pmk := range s.PMKs {
			ssid = strings.ToLower(ssid)
			if len(pmk) == 32 {
				pmks[ssid] = append(pmks[ssid], append([]byte(nil), pmk...))
			}
			for _, more := range s.More[ssid] {
				if len(more) == 32 {
					pmks[ssid] = append(pmks[ssid], append([]byte(nil), more...))
				}
			}
		}
		for i, b := range s.WEP {
			wep[i] = append([]byte(nil), b...)
		}
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	holds := func(list [][]byte, pmk []byte) bool {
		return slices.ContainsFunc(list, func(b []byte) bool { return bytes.Equal(b, pmk) })
	}
	for key, src := range k.pairNet {
		if !holds(pmks[src.ssid], k.pairPMK[key]) {
			delete(k.pairs, key)
			delete(k.pairNet, key)
			delete(k.pairPMK, key)
		}
	}
	for bssid, g := range k.groups {
		// A group key came through one of the network's PMKs. Another being added doesn't
		// touch it; losing all of them does.
		if !slices.ContainsFunc(k.pmks[g.ssid], func(b []byte) bool { return holds(pmks[g.ssid], b) }) {
			delete(k.groups, bssid)
		}
	}
	k.pmks = pmks
	k.wep = wep
}

// AddPassphrase registers a WPA/WPA2 passphrase for an SSID.
func (k *Keyring) AddPassphrase(ssid, pass string) error {
	pmk, err := PMK(pass, ssid)
	if err != nil {
		return err
	}
	k.mu.Lock()
	k.pmks[strings.ToLower(ssid)] = [][]byte{pmk}
	k.mu.Unlock()
	return nil
}

// AddPMK registers a raw 32-byte PMK for an SSID. This is the hook for WPA3
// SAE keys obtained by other means, and for WPA2-EAP.
func (k *Keyring) AddPMK(ssid string, pmk []byte) error {
	if len(pmk) != 32 {
		return fmt.Errorf("wifi: PMK must be 32 bytes")
	}
	k.mu.Lock()
	k.pmks[strings.ToLower(ssid)] = [][]byte{append([]byte(nil), pmk...)}
	k.mu.Unlock()
	return nil
}

// AddWEPKey sets one of the four WEP keys from hex. index is 0..3.
func (k *Keyring) AddWEPKey(index int, hexKey string) error {
	b, err := ParseWEPKey(index, hexKey)
	if err != nil {
		return err
	}
	k.mu.Lock()
	k.wep[index] = b
	k.mu.Unlock()
	return nil
}

// Network is the SSID and security last seen for a BSSID.
func (k *Keyring) Network(bssid string) (string, Security, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	n, ok := k.networks[strings.ToLower(bssid)]
	return n.ssid, n.security, ok
}

func (k *Keyring) setNetwork(bssid, ssid string, s Security) {
	if bssid == "" {
		return
	}
	key := strings.ToLower(bssid)
	k.mu.Lock()
	if len(k.networks) > 50_000 {
		evict(k.networks, 45_000)
	}
	old := k.networks[key]
	if ssid == "" {
		// Hidden beacons and probe responses must not erase a name seen
		// in an association request or key data.
		ssid = old.ssid
	}
	if s.Kind == "" {
		s = old.security
	}
	k.networks[key] = network{ssid: ssid, security: s}
	k.mu.Unlock()
}

func (k *Keyring) pmkFor(ssid string) []byte {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if all := k.pmks[strings.ToLower(ssid)]; len(all) > 0 {
		return append([]byte(nil), all[0]...)
	}
	return nil
}

// pmksFor is every PMK a network has. They're replaced whole, never changed, so sharing is fine.
func (k *Keyring) pmksFor(ssid string) [][]byte {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return slices.Clone(k.pmks[strings.ToLower(ssid)])
}

// evict removes arbitrary entries until m holds at most keep. Map order is
// random, which is enough for a cache under memory pressure; the alternative
// (clearing it) loses every key at once.
func evict[K comparable, V any](m map[K]V, keep int) {
	for k := range m {
		if len(m) <= keep {
			return
		}
		delete(m, k)
	}
}

func pairKey(ap, sta net.HardwareAddr) string {
	return strings.ToLower(ap.String() + "|" + sta.String())
}

// ProcessEAPOL follows one 4-way handshake message, verifies it when
// possible, and installs the PTK once message 2 or 3 completes the nonces.
func (k *Keyring) ProcessEAPOL(f *Frame, msg *EAPOLKey) HandshakeInfo {
	info := HandshakeInfo{Message: msg.Message(), Version: msg.Version(), Cipher: msg.Cipher()}
	if msg.Request() || msg.Error() {
		return info
	}
	if !msg.Pairwise() {
		return k.processGroupKey(f, msg, info)
	}
	if info.Message == 0 {
		return info
	}
	ap, sta := f.BSSID, f.Dst
	if info.Message == 2 || info.Message == 4 {
		ap, sta = f.BSSID, f.Src
	}
	if ap == nil || sta == nil {
		info.Err = fmt.Errorf("eapol: cannot identify AP/station")
		return info
	}
	key := pairKey(ap, sta)
	k.mu.Lock()
	hs := k.handshakes[key]
	if hs == nil {
		if len(k.handshakes) > 50_000 {
			evict(k.handshakes, 45_000)
		}
		hs = &handshake{}
		k.handshakes[key] = hs
	}
	switch info.Message {
	case 1:
		hs.anonce = append([]byte(nil), msg.Nonce[:]...)
	case 2:
		hs.snonce = append([]byte(nil), msg.Nonce[:]...)
		hs.cipher, hs.akm = rsnChoice(msg.KeyData)
	case 3:
		hs.anonce = append([]byte(nil), msg.Nonce[:]...)
	}
	anonce, snonce, cipher, akm := hs.anonce, hs.snonce, hs.cipher, hs.akm
	k.mu.Unlock()
	if info.Message == 1 {
		// It only carries the authenticator nonce; message 2 completes
		// the pair and can be verified against the PTK.
		return info
	}

	ssid, _, known := k.Network(ap.String())
	if !known && len(msg.KeyData) > 0 {
		if ie := keyDataSSID(msg.KeyData); ie != "" {
			ssid = ie
		}
	}
	if ssid == "" || len(anonce) != 32 || len(snonce) != 32 {
		return info
	}
	pmks := k.pmksFor(ssid)
	if len(pmks) == 0 {
		// No passphrase/PMK: the frame is still useful as an
		// observation, but no key can be derived.
		return info
	}
	if msg.Version() == 0 && akm != "" && akm != "SAE" && akm != "OWE" {
		info.Err = errUnsupportedKey // its keys and MICs are other lengths: report it, don't guess
		return info
	}
	msg.AKM = akm
	// The MIC is what proves a PMK is this handshake's. Nothing is installed without it.
	var split *PTK
	var pmk []byte
	for _, candidate := range pmks {
		p, err := derivePair(candidate, ap, sta, anonce, snonce, msg.Version(), cipher)
		if err != nil {
			info.Err = err
			return info
		}
		ok, err := msg.VerifyMIC(p.KCK)
		if err != nil {
			info.Err = err
			return info
		}
		if ok {
			split, pmk = p, candidate
			break
		}
	}
	if split == nil {
		info.Valid = false
		return info
	}
	info.Valid = true
	info.Chosen = cipher
	k.install(key, newPairSource(ssid, anonce, snonce), split, pmk)
	info.Installed = true
	if info.Message == 3 {
		// Message 3 carries the AP's current GTK, wrapped with the KEK.
		id, ok, err := k.installGTK(ap.String(), ssid, msg, split.KEK, f.TS)
		info.GTK, info.Err = ok, err
		if ok {
			info.GroupKey = record(ap, sta, ssid, id, newPairSource(ssid, anonce, snonce), msg, f.TS)
		}
	}
	info.SSID, info.AP, info.STA = ssid, ap.String(), sta.String()
	info.ANonce = append([]byte(nil), anonce...)
	info.SNonce = append([]byte(nil), snonce...)
	return info
}

// LoadHandshake re-derives and installs a pairwise key from a stored
// handshake: the public nonces plus the PMK the server supplied for ssid. It returns
// false (no error) when no PMK is known for the SSID, since nothing can be
// derived then. This is how a restarted or additional sensor recovers keys
// from the server without re-capturing the 4-way handshake.
func (k *Keyring) LoadHandshake(bssid, sta, ssid string, anonce, snonce []byte, keyVersion int) (bool, error) {
	return k.LoadHandshakeCipher(bssid, sta, ssid, anonce, snonce, keyVersion, "")
}

// LoadHandshakeCipher is LoadHandshake with the pairwise cipher the station
// chose in message 2, so a re-derived key does not guess from the beacon.
func (k *Keyring) LoadHandshakeCipher(bssid, sta, ssid string, anonce, snonce []byte, keyVersion int, cipher string) (bool, error) {
	if len(anonce) != 32 || len(snonce) != 32 {
		return false, fmt.Errorf("wifi: handshake nonce must be 32 bytes")
	}
	ap, err := net.ParseMAC(bssid)
	if err != nil {
		return false, err
	}
	st, err := net.ParseMAC(sta)
	if err != nil {
		return false, err
	}
	key, src := pairKey(ap, st), newPairSource(ssid, anonce, snonce)
	k.mu.RLock()
	installed, ok := k.pairNet[key]
	k.mu.RUnlock()
	if ok && installed == src {
		// Already derived from this handshake, and SetSecrets drops a key
		// whose PMK changed: nothing to redo on a periodic resync.
		return true, nil
	}
	// A stored handshake has no MIC to check a PMK against, so this needs there to be only
	// the one. A network with several gets its keys from a handshake seen live.
	pmks := k.pmksFor(ssid)
	if len(pmks) != 1 {
		return false, nil
	}
	installedKey, err := derivePair(pmks[0], ap, st, anonce, snonce, keyVersion, cipher)
	if err != nil {
		return false, err
	}
	k.install(key, src, installedKey, pmks[0])
	return true, nil
}

// install records a pairwise key and what it was derived from.
func (k *Keyring) install(key string, src pairSource, ptk *PTK, pmk []byte) {
	k.mu.Lock()
	if len(k.pairs) > 50_000 {
		// Evict some, not all: clearing the map drops every client's
		// working key at once during a guest-network MAC rotation.
		for old := range k.pairs {
			if len(k.pairs) <= 45_000 {
				break
			}
			delete(k.pairs, old)
			delete(k.pairNet, old)
			delete(k.pairPMK, old)
		}
	}
	k.pairs[key] = ptk
	k.pairNet[key] = src
	k.pairPMK[key] = pmk
	k.mu.Unlock()
}

// keyDataSSID pulls an SSID out of an EAPOL-Key data field when a probe
// response is embedded there.
func keyDataSSID(b []byte) string {
	if ies, err := parseIEs(b); err == nil {
		return ies.SSID()
	}
	return ""
}

// hasPTK reports whether a pairwise key is known for a station.
func (k *Keyring) ptk(ap, sta string) *PTK {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.pairs[strings.ToLower(ap+"|"+sta)]
}

// decrypt is Decrypt with an option for a MAC fragment. TKIP's Michael MIC
// covers the whole MSDU, so a fragmented TKIP frame must not verify it until
// the pieces are joined. A non-nil tkipMIC tells the caller to verify it
// after reassembly; the returned plaintext then still includes the MIC bytes.
func (k *Keyring) decrypt(f *Frame, fragment bool) ([]byte, string, *tkipMIC, error) {
	if !f.Protected {
		_, payload, err := f.LLC()
		return payload, "none", nil, err
	}
	body := f.Body
	if len(body) < 8 {
		return nil, "", nil, fmt.Errorf("wifi: short protected frame")
	}
	ap := f.BSSID.String()
	if f.FromDS && !f.ToDS && len(f.Dst) == 6 && f.Dst[0]&1 != 0 {
		// Broadcast/multicast from the AP: the group key, by key ID.
		if gk := k.group(ap, int(body[3]>>6)); gk != nil {
			if f.Src != nil && k.ptk(ap, f.Src.String()) != nil {
				return nil, "", nil, errRelayed
			}
			_, sec, _ := k.Network(ap)
			if strings.HasPrefix(sec.Group, "GCMP") {
				out, err := gcmpDecrypt(f.rawHeader(), body, gk.tk)
				return out, sec.Group, nil, err
			}
			if gk.tkip {
				out, mic, err := tkipOpen(f.rawHeader(), body, gk.tk, true, !fragment)
				return out, "TKIP", mic, err
			}
			out, err := ccmpDecrypt(f.rawHeader(), body, gk.tk)
			return out, "CCMP", nil, err
		}
	}
	var sta string
	switch {
	case f.FromDS && !f.ToDS:
		sta = f.Dst.String() // the access point is sending to the station
	case f.ToDS && !f.FromDS:
		sta = f.Src.String() // the station is sending
	default:
		// A four-address frame has no BSSID to key a pairwise PTK
		// against; WEP below still applies.
	}
	if sta != "" {
		if ptk := k.ptk(ap, sta); ptk != nil {
			if ptk.TKIP {
				out, mic, err := tkipOpen(f.rawHeader(), body, ptk.TK, f.FromDS && !f.ToDS, !fragment)
				return out, "TKIP", mic, err
			}
			_, sec, _ := k.Network(ap)
			switch c := pairwiseCipher(ptk.Cipher, sec); c {
			case "GCMP-128":
				out, err := gcmpDecrypt(f.rawHeader(), body, ptk.TK)
				return out, c, nil, err
			case "GCMP-256":
				if len(ptk.TK256) != 32 {
					return nil, "", nil, fmt.Errorf("wifi: no 256-bit temporal key")
				}
				out, err := gcmpDecrypt(f.rawHeader(), body, ptk.TK256)
				return out, c, nil, err
			case "CCMP-256":
				if len(ptk.TK256) != 32 {
					return nil, "", nil, fmt.Errorf("wifi: no 256-bit temporal key")
				}
				out, err := ccmpDecrypt(f.rawHeader(), body, ptk.TK256)
				return out, c, nil, err
			}
			out, err := ccmpDecrypt(f.rawHeader(), body, ptk.TK)
			return out, "CCMP", nil, err
		}
	}
	// WEP has no handshake: try the configured keys.
	k.mu.RLock()
	keys := k.wep
	k.mu.RUnlock()
	out, err := wepDecrypt(body, keys)
	return out, "WEP", nil, err
}

// Decrypt decrypts a complete protected data frame.
func (k *Keyring) Decrypt(f *Frame) ([]byte, string, error) {
	out, cipher, _, err := k.decrypt(f, false)
	return out, cipher, err
}

// rawHeader returns the MAC header bytes, which Decrypt needs for AAD and
// Michael. Frame keeps them separately because Body aliases the capture.
func (f *Frame) rawHeader() []byte { return f.header }

// Keys returns the number of installed PTKs, for status and tests.
func (k *Keyring) Keys() int {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return len(k.pairs)
}
