package backup

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/xen0bit/netgraph/internal/policy"
)

func testBundle(t *testing.T) *Bundle {
	t.Helper()
	b := New()
	b.Policies = []*policy.Policy{{
		Version: 2, Name: "home",
		Defaults: policy.Defaults{Egress: "deny", Ingress: "deny", IntraZone: "allow", DNS: "allow"},
		RulesV2:  []policy.RuleV2{{Name: "web", Action: policy.ActionAllow, Local: policy.Selector{Type: "any"}, Remote: policy.Selector{Type: "domain", Values: []string{"example.com"}}}},
	}}
	return b
}

func TestRoundTripAndSignature(t *testing.T) {
	b := testBundle(t)
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	raw, err := Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "decisions") {
		t.Fatal("bundle leaked decisions")
	}
	got, err := Parse(strings.NewReader(string(raw)))
	if err != nil || len(got.Policies) != 1 {
		t.Fatalf("parse = %+v, %v", got, err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	env, err := Sign(raw, priv)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(env, pub)
	if err != nil || string(verified) != string(raw) {
		t.Fatalf("verify = %v", err)
	}
	env.Payload = string(append([]byte(env.Payload), 'x'))
	if _, err := Verify(env, pub); err == nil {
		t.Fatal("tampered bundle verified")
	}
}

func TestEncryption(t *testing.T) {
	b := testBundle(t)
	raw, _ := Marshal(b)
	env, err := Encrypt(raw, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decrypt(env, "correct horse")
	if err != nil || string(got) != string(raw) {
		t.Fatalf("decrypt = %v", err)
	}
	if _, err := Decrypt(env, "wrong"); err == nil {
		t.Fatal("wrong password decrypted")
	}
}
