// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestIsPermanentSSHDialError(t *testing.T) {
	keyErr := &knownhosts.KeyError{}
	if !isPermanentSSHDialError(keyErr) {
		t.Fatal("expected knownhosts.KeyError to be permanent")
	}
	if !isPermanentSSHDialError(fmt.Errorf("wrap: %w", keyErr)) {
		t.Fatal("expected wrapped knownhosts.KeyError to be permanent")
	}
	authErr := errors.New("ssh: unable to authenticate, attempted methods [none publickey], no supported methods remain")
	if !isPermanentSSHDialError(authErr) {
		t.Fatal("expected client authentication failure to be permanent")
	}
	if !isPermanentSSHDialError(errors.New("ssh: handshake failed: host key mismatch")) {
		t.Fatal("expected host key mismatch message to be permanent")
	}
	if isPermanentSSHDialError(errors.New("connection refused")) {
		t.Fatal("connection refused should be retried")
	}
}

func TestGetSSHClientPropagatesHostKeyError(t *testing.T) {
	hostKeyErr := errors.New("host key rejected for test")
	restore := stubSSHDial(func(_ string, _ string, _ *ssh.ClientConfig) (*ssh.Client, error) {
		return nil, hostKeyErr
	})
	defer restore()

	signer := testSigner(t)
	_, err := getSshClient("user", "127.0.0.1:22", signer, ssh.InsecureIgnoreHostKey())
	if err == nil {
		t.Fatal("expected dial error")
	}
	if !strings.Contains(err.Error(), "failed to initiate SSH connection") {
		t.Fatalf("expected context in error, got %v", err)
	}
	if !errors.Is(err, hostKeyErr) {
		t.Fatalf("expected host key error to propagate, got %v", err)
	}
}

func TestGetSSHClientFailsFastOnAuthenticationError(t *testing.T) {
	authErr := errors.New("ssh: unable to authenticate, attempted methods [none publickey], no supported methods remain")
	restore := stubSSHDial(func(_ string, _ string, _ *ssh.ClientConfig) (*ssh.Client, error) {
		return nil, authErr
	})
	defer restore()

	signer := testSigner(t)
	_, err := getSshClient("user", "127.0.0.1:22", signer, ssh.InsecureIgnoreHostKey())
	if err == nil {
		t.Fatal("expected dial error")
	}
	if !errors.Is(err, authErr) {
		t.Fatalf("expected authentication error to propagate, got %v", err)
	}
}

func stubSSHDial(fn func(string, string, *ssh.ClientConfig) (*ssh.Client, error)) func() {
	prev := sshDial
	sshDial = fn
	return func() { sshDial = prev }
}

func testSigner(t *testing.T) ssh.Signer {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}
	return signer
}
