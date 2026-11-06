package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/xen0bit/netgraph/internal/backup"
)

func readOrStdin(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func runPolicyBackup(args []string) error {
	fs := flag.NewFlagSet("policy backup", flag.ContinueOnError)
	var b backendFlags
	b.register(fs)
	out := fs.String("out", "-", "output file; - writes stdout")
	passwordFile := fs.String("password-file", "", "encrypt the bundle with the password in this file; default $NETGRAPH_BUNDLE_PASSWORD")
	signKey := fs.String("sign-key", "", "hex Ed25519 private key file: sign the bundle instead of encrypting it")
	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	password, err := readSecret(*passwordFile, "NETGRAPH_BUNDLE_PASSWORD")
	if err != nil {
		return err
	}
	if password != "" && *signKey != "" {
		return errors.New("a bundle is either encrypted (-password-file) or signed (-sign-key), not both")
	}
	be, closeFn, err := openPolicyBackend(&b)
	if err != nil {
		return err
	}
	defer closeFn()
	bundle, err := be.ExportBundle(context.Background())
	if err != nil {
		return err
	}
	raw, err := backup.Marshal(bundle)
	if err != nil {
		return err
	}
	var data []byte
	switch {
	case password != "":
		env, err := backup.Encrypt(raw, password)
		if err != nil {
			return err
		}
		data, err = json.MarshalIndent(env, "", "  ")
		if err != nil {
			return err
		}
	case *signKey != "":
		key, err := readEd25519Key(*signKey)
		if err != nil {
			return err
		}
		env, err := backup.Sign(raw, key)
		if err != nil {
			return err
		}
		data, err = json.MarshalIndent(env, "", "  ")
		if err != nil {
			return err
		}
	default:
		data = raw
	}
	if *out == "-" {
		_, err = os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(*out, data, 0o600)
}

func readEd25519Key(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, err
	}
	switch len(b) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(b), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(b), nil
	default:
		return nil, fmt.Errorf("key is %d bytes, want 32 or 64", len(b))
	}
}

// openBundleFile reads a plain, encrypted or signed bundle. It fails closed:
// given a verify key, only a bundle with a good signature is accepted.
func openBundleFile(path, password, verifyKey string) (*backup.Bundle, error) {
	raw, err := readOrStdin(path)
	if err != nil {
		return nil, err
	}
	var env backup.Envelope
	isEnvelope := json.Unmarshal(raw, &env) == nil && env.Encoding != ""
	if verifyKey != "" && (!isEnvelope || env.Encoding != "signed") {
		return nil, errors.New("-verify-key given, but the bundle is not signed")
	}
	if !isEnvelope {
		return backup.Parse(strings.NewReader(string(raw)))
	}
	switch env.Encoding {
	case "encrypted":
		if password == "" {
			return nil, errors.New("the bundle is encrypted: give -password-file or $NETGRAPH_BUNDLE_PASSWORD")
		}
		payload, err := backup.Decrypt(&env, password)
		if err != nil {
			return nil, errors.New("the bundle does not decrypt with that password, or was changed")
		}
		return backup.Parse(strings.NewReader(string(payload)))
	case "signed":
		if verifyKey == "" {
			return nil, errors.New("the bundle is signed: give -verify-key to check it")
		}
		pub, err := readEd25519Public(verifyKey)
		if err != nil {
			return nil, err
		}
		payload, err := backup.Verify(&env, pub)
		if err != nil {
			return nil, err
		}
		return backup.Parse(strings.NewReader(string(payload)))
	}
	return nil, fmt.Errorf("unknown bundle encoding %q", env.Encoding)
}

func readEd25519Public(path string) (ed25519.PublicKey, error) {
	keyRaw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(keyRaw)))
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("verify key must be 32 hex-encoded bytes")
	}
	return ed25519.PublicKey(key), nil
}

func runPolicyRestore(args []string) error {
	fs := flag.NewFlagSet("policy restore", flag.ContinueOnError)
	var b backendFlags
	b.register(fs)
	path := fs.String("file", "", "bundle file; - reads stdin")
	passwordFile := fs.String("password-file", "", "decrypt with the password in this file; default $NETGRAPH_BUNDLE_PASSWORD")
	verifyKey := fs.String("verify-key", "", "hex Ed25519 public key file; with it, only a bundle signed by that key is restored")
	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *path == "" {
		return errors.New("usage: netgraph policy restore -file bundle.json")
	}
	password, err := readSecret(*passwordFile, "NETGRAPH_BUNDLE_PASSWORD")
	if err != nil {
		return err
	}
	bundle, err := openBundleFile(*path, password, *verifyKey)
	if err != nil {
		return err
	}
	be, closeFn, err := openPolicyBackendFor(&b, true)
	if err != nil {
		return err
	}
	defer closeFn()
	counts, err := be.ImportBundle(context.Background(), bundle)
	if err != nil {
		return err
	}
	return encode(counts)
}

func runPolicyVerify(args []string) error {
	fs := flag.NewFlagSet("policy verify", flag.ContinueOnError)
	path := fs.String("file", "", "signed envelope file")
	verifyKey := fs.String("verify-key", "", "hex Ed25519 public key file")
	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *path == "" || *verifyKey == "" {
		return errors.New("usage: netgraph policy verify -file signed.json -verify-key pub.hex")
	}
	bundle, err := openBundleFile(*path, "", *verifyKey)
	if err != nil {
		return err
	}
	return encode(map[string]any{"valid": true, "policies": len(bundle.Policies), "blocklists": len(bundle.Blocklists)})
}
