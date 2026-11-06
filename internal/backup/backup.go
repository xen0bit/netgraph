// Package backup moves policy configuration between netgraph servers. A
// bundle contains configuration, never observations, tokens or keys. It can
// be encrypted with a password and signed with Ed25519.
package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/policy"
)

// Bundle format version.
const Version = 1

// Bundle is a portable policy configuration.
type Bundle struct {
	Version    int                    `json:"version"`
	Exported   int64                  `json:"exported"`
	Policies   []*policy.Policy       `json:"policies"`
	Profiles   []model.Profile        `json:"profiles"`
	Triggers   []model.NetworkTrigger `json:"network_triggers"`
	RuleGroups []model.RuleGroup      `json:"rule_groups,omitempty"`
	Blocklists []BlocklistBundle      `json:"blocklists"`
	Purposes   []model.Purpose        `json:"purposes"`
}

// BlocklistBundle is one list and its entries.
type BlocklistBundle struct {
	List    model.Blocklist        `json:"list"`
	Entries []model.BlocklistEntry `json:"entries"`
}

// New returns an empty bundle stamped now.
func New() *Bundle {
	return &Bundle{Version: Version, Exported: time.Now().UTC().UnixMilli()}
}

// Validate checks the parts that must be loadable.
func (b *Bundle) Validate() error {
	if b.Version != Version {
		return fmt.Errorf("bundle version %d is not supported", b.Version)
	}
	for _, p := range b.Policies {
		if p == nil {
			return fmt.Errorf("bundle has a nil policy")
		}
		if err := p.Validate(); err != nil {
			return fmt.Errorf("policy %q: %w", p.Name, err)
		}
	}
	for _, pr := range b.Profiles {
		if pr.Name == "" {
			return fmt.Errorf("bundle has a profile without a name")
		}
	}
	return nil
}

// Marshal returns the canonical bundle bytes.
func Marshal(b *Bundle) ([]byte, error) {
	if b == nil {
		return nil, fmt.Errorf("no bundle")
	}
	if err := b.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(b)
}

// Parse reads a bundle strictly.
func Parse(r io.Reader) (*Bundle, error) {
	var b Bundle
	dec := json.NewDecoder(io.LimitReader(r, 64<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return nil, err
	}
	if err := b.Validate(); err != nil {
		return nil, err
	}
	return &b, nil
}

// Envelope is a signed or encrypted bundle.
type Envelope struct {
	Version    int    `json:"version"`
	Encoding   string `json:"encoding"` // json, signed, encrypted
	Payload    string `json:"payload"`  // base64
	Signature  string `json:"signature,omitempty"`
	Salt       string `json:"salt,omitempty"`
	Nonce      string `json:"nonce,omitempty"`
	Ciphertext string `json:"ciphertext,omitempty"`
}

// Sign wraps bundle bytes with an Ed25519 signature. The signature covers the
// exact payload bytes.
func Sign(payload []byte, priv ed25519.PrivateKey) (*Envelope, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("bad private key")
	}
	sig := ed25519.Sign(priv, payload)
	return &Envelope{Version: Version, Encoding: "signed", Payload: base64.StdEncoding.EncodeToString(payload), Signature: base64.StdEncoding.EncodeToString(sig)}, nil
}

// Verify checks a signed envelope. It fails closed.
func Verify(e *Envelope, pub ed25519.PublicKey) ([]byte, error) {
	if e == nil || e.Encoding != "signed" {
		return nil, fmt.Errorf("not a signed envelope")
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("bad public key")
	}
	payload, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil {
		return nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(e.Signature)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(pub, payload, sig) {
		return nil, fmt.Errorf("signature does not verify")
	}
	return payload, nil
}

// Encrypt wraps bundle bytes with AES-256-GCM and a PBKDF2-derived key. A
// fresh random salt and nonce are used every time.
func Encrypt(payload []byte, password string) (*Envelope, error) {
	if password == "" {
		return nil, fmt.Errorf("empty password")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, 200_000, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, payload, nil)
	return &Envelope{
		Version: Version, Encoding: "encrypted",
		Salt: base64.StdEncoding.EncodeToString(salt), Nonce: base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
	}, nil
}

// Decrypt opens an encrypted envelope.
func Decrypt(e *Envelope, password string) ([]byte, error) {
	if e == nil || e.Encoding != "encrypted" {
		return nil, fmt.Errorf("not an encrypted envelope")
	}
	salt, err := base64.StdEncoding.DecodeString(e.Salt)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(e.Nonce)
	if err != nil {
		return nil, err
	}
	ct, err := base64.StdEncoding.DecodeString(e.Ciphertext)
	if err != nil {
		return nil, err
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, 200_000, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ct, nil)
}

// ParseEnvelope reads an envelope strictly.
func ParseEnvelope(r io.Reader) (*Envelope, error) {
	var e Envelope
	dec := json.NewDecoder(io.LimitReader(r, 128<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return nil, err
	}
	if e.Version != Version {
		return nil, fmt.Errorf("envelope version %d is not supported", e.Version)
	}
	return &e, nil
}
