package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestKnownHostsBuildsFromPrivateKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	wrapper := skelpipeToWrapper{
		skelpipeWrapper: skelpipeWrapper{
			pipe: &pipeConfig{
				UpstreamHost: "example.com:2222",
				KnownHosts: keydata{
					Data: string(pemBytes),
				},
			},
		},
	}

	line, err := wrapper.KnownHosts(nil)
	if err != nil {
		t.Fatalf("known hosts generation failed: %v", err)
	}

	got := string(line)
	if !strings.Contains(got, "[example.com]:2222") {
		t.Fatalf("expected host pattern in known hosts line, got %q", got)
	}

	pub, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("failed to derive public key: %v", err)
	}

	expectedFragment := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
	if !strings.Contains(got, expectedFragment) {
		t.Fatalf("known hosts line missing public key fragment %q, got %q", expectedFragment, got)
	}
}
