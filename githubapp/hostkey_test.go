package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func testPublicKey(t *testing.T) (ssh.PublicKey, []byte) {
	t.Helper()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("unable to generate test key: %v", err)
	}

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("unable to create ssh public key: %v", err)
	}

	return sshPub, sshPub.Marshal()
}

func TestVerifyHostKeyFromKnownHosts(t *testing.T) {
	host := "[127.0.0.1]:22"
	netaddr := "127.0.0.1:22"

	matchPub, matchKey := testPublicKey(t)
	_, mismatchKey := testPublicKey(t)

	tests := []struct {
		name           string
		knownHostsData string
		key            []byte
		wantErr        bool
	}{
		{
			name:           "matching host key",
			knownHostsData: knownhosts.Line([]string{host}, matchPub),
			key:            matchKey,
		},
		{
			name:           "mismatched host key",
			knownHostsData: knownhosts.Line([]string{host}, matchPub),
			key:            mismatchKey,
			wantErr:        true,
		},
		{
			name:           "malformed known_hosts data",
			knownHostsData: "not a known_hosts line",
			key:            matchKey,
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyHostKeyFromKnownHosts(strings.NewReader(tt.knownHostsData), host, netaddr, tt.key)
			if tt.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
