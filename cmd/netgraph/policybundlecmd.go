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
	password := fs.String("password", "", "encrypt the bundle with this password")
	signKey := fs.String("sign-key", "", "hex Ed25519 private key file")
	if err := parseInterspersed(fs, args); err != nil {
		return err
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
	case *password != "":
		env, err := backup.Encrypt(raw, *password)
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

func openBundleFile(path, password, verifyKey string) (*backup.Bundle, error) {
	raw, err := readOrStdin(path)
	if err != nil {
		return nil, err
	}
	var env backup.Envelope
	if json.Unmarshal(raw, &env) == nil && env.Encoding != "" {
		switch env.Encoding {
		case "encrypted":
			payload, err := backup.Decrypt(&env, password)
			if err != nil {
				return nil, err
			}
			return backup.Parse(strings.NewReader(string(payload)))
		case "signed":
			keyRaw, err := os.ReadFile(verifyKey)
			if err != nil {
				return nil, err
			}
			key, err := hex.DecodeString(strings.TrimSpace(string(keyRaw)))
			if err != nil || len(key) != ed25519.PublicKeySize {
				return nil, errors.New("verify key must be 32 hex-encoded bytes")
			}
			payload, err := backup.Verify(&env, ed25519.PublicKey(key))
			if err != nil {
				return nil, err
			}
			return backup.Parse(strings.NewReader(string(payload)))
		}
	}
	return backup.Parse(strings.NewReader(string(raw)))
}

func runPolicyRestore(args []string) error {
	fs := flag.NewFlagSet("policy restore", flag.ContinueOnError)
	var b backendFlags
	b.register(fs)
	path := fs.String("file", "", "bundle file; - reads stdin")
	password := fs.String("password", "", "decrypt with this password")
	verifyKey := fs.String("verify-key", "", "hex Ed25519 public key file")
	if err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *path == "" {
		return errors.New("usage: netgraph policy restore -file bundle.json")
	}
	bundle, err := openBundleFile(*path, *password, *verifyKey)
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
	raw, err := os.ReadFile(*path)
	if err != nil {
		return err
	}
	var env backup.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return err
	}
	keyRaw, err := os.ReadFile(*verifyKey)
	if err != nil {
		return err
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(keyRaw)))
	if err != nil || len(key) != ed25519.PublicKeySize {
		return errors.New("verify key must be 32 hex-encoded bytes")
	}
	payload, err := backup.Verify(&env, ed25519.PublicKey(key))
	if err != nil {
		return err
	}
	if _, err := backup.Parse(strings.NewReader(string(payload))); err != nil {
		return err
	}
	return encode(map[string]any{"valid": true, "bytes": len(payload)})
}
