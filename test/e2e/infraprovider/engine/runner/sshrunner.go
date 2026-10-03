// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/api"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"k8s.io/apimachinery/pkg/util/wait"
)

var sshDial = func(network, address string, config *ssh.ClientConfig) (*ssh.Client, error) {
	return ssh.Dial(network, address, config)
}

// SSHOptions configures host-key verification for NewSSHRunner.
type SSHOptions struct {
	KnownHostsPath  string
	InsecureHostKey bool
}

func (o SSHOptions) hostKeyCallback() (ssh.HostKeyCallback, error) {
	if o.InsecureHostKey {
		return ssh.InsecureIgnoreHostKey(), nil
	}
	path := o.KnownHostsPath
	if path == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			path = filepath.Join(home, ".ssh", "known_hosts")
		}
	}
	if path != "" {
		if _, err := os.Stat(path); err == nil {
			return knownhosts.New(path)
		}
	}
	return nil, fmt.Errorf("SSH host key verification required: set OVN_TEST_SSH_KNOWN_HOSTS or OVN_TEST_SSH_INSECURE_HOST_KEY=1")
}

// Run implements api.Runner interface to run commands over SSH.
type sshRunner struct {
	ip              string
	user            string
	port            string
	signer          ssh.Signer
	hostKeyCallback ssh.HostKeyCallback
	mu              sync.Mutex
	client          *ssh.Client
}

// NewSSHRunner connects over SSH with insecure host-key verification. It
// preserves the original four-argument API for existing callers (for example
// downstream bare-metal adapters). Prefer NewSSHRunnerWithOptions when host-key
// verification is required.
func NewSSHRunner(ip, user, port, privateKeyFilePath string) (api.Runner, error) {
	return NewSSHRunnerWithOptions(ip, user, port, privateKeyFilePath, SSHOptions{InsecureHostKey: true})
}

// NewSSHRunnerWithOptions connects over SSH using the supplied host-key policy.
func NewSSHRunnerWithOptions(ip, user, port, privateKeyFilePath string, opts SSHOptions) (api.Runner, error) {
	// Parse SSH private key
	signer, err := makePrivateKeySignerFromFile(privateKeyFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ssh key file: %w", err)
	}
	hostKeyCallback, err := opts.hostKeyCallback()
	if err != nil {
		return nil, err
	}
	return &sshRunner{
		ip:              ip,
		port:            port,
		user:            user,
		signer:          signer,
		hostKeyCallback: hostKeyCallback,
	}, nil
}

func (s *sshRunner) Run(command string, args ...string) (string, error) {
	// Build the command string (e.g., "podman network inspect kind")
	var cmdParts []string
	cmdParts = append(cmdParts, command)
	cmdParts = append(cmdParts, args...)

	// Execute via SSH on the remote node
	sshClient, err := s.getSSHClient()
	if err != nil {
		return "", err
	}
	result, err := runSSHCommand(sshClient, cmdParts)
	if err != nil {
		return "", fmt.Errorf("failed to run command for %s@%s, result: %v, err: %w",
			s.user, s.ip, result, err)
	}
	return result.stdout, nil
}

// getSSHClient returns the cached SSH client to the remote IP, creating it if needed.
// If the existing connection is broken, it will be recreated.
func (s *sshRunner) getSSHClient() (*ssh.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// If we already have a client, verify it's still alive
	if s.client != nil {
		// Quick check: try to create a session
		session, err := s.client.NewSession()
		if err == nil {
			defer func() {
				err = session.Close()
				if err != nil {
					ginkgo.GinkgoLogr.Info("error closing ssh session", "error", err)
				}
			}()
			return s.client, nil
		}
		// Connection is dead, close it and create a new one
		s.client.Close()
		s.client = nil
	}

	// Create new connection
	client, err := getSshClient(s.user, net.JoinHostPort(s.ip, s.port), s.signer, s.hostKeyCallback)
	if err != nil {
		return nil, fmt.Errorf("error getting ssh proxy client: %w", err)
	}

	s.client = client
	return s.client, nil
}

// Close closes the cached SSH client, if any, and is safe to call multiple times.
// It only tears down the cached transport; it is NOT command cancellation. A Run
// executing concurrently may already hold a session, in which case that command
// simply fails if Close races it (normal shutdown behavior); the struct's fields
// stay mutex-protected. Callers holding an api.Runner reach this via a type
// assertion to interface{ Close() error }.
func (s *sshRunner) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.client == nil {
		return nil
	}
	err := s.client.Close()
	s.client = nil
	return err
}

// result holds the execution result of SSH command
type result struct {
	user   string
	ip     string
	cmd    string
	stdout string
	stderr string
}

func (r result) String() string {
	return fmt.Sprintf("User: %q, IP: %q, Command: %q, Stdout: %q, Stderr: %q",
		r.user, r.ip, r.cmd, r.stdout, r.stderr)
}

// runSSHCommand returns the stdout, stderr, and exit code from running cmd on
// host as specific user, along with any SSH-level error.
func runSSHCommand(sshClient *ssh.Client, cmdArgs []string) (result, error) {
	res := result{}
	user := sshClient.User()
	addr := sshClient.RemoteAddr().String()
	session, err := sshClient.NewSession()
	if err != nil {
		return res, fmt.Errorf("failed creating new ssh session with %s@%s: %w", user, addr, err)
	}
	defer session.Close()

	var quotedArgs []string
	for _, arg := range cmdArgs {
		quotedArgs = append(quotedArgs, shellQuote(arg))
	}
	cmd := strings.Join(quotedArgs, " ")

	// Run the command.
	var bout, berr bytes.Buffer
	session.Stdout, session.Stderr = &bout, &berr
	if err = session.Run(cmd); err != nil {
		err = fmt.Errorf("failed to run command `%s` on %s@%s: %w", cmd, user, addr, err)
	}
	res.cmd = cmd
	res.stdout = bout.String()
	res.stderr = berr.String()
	res.user = user
	res.ip = addr
	return res, err
}

func getSshClient(user, addr string, signer ssh.Signer, hostKeyCallback ssh.HostKeyCallback) (*ssh.Client, error) {
	const overallTimeout = 20 * time.Second
	const perDialTimeout = 10 * time.Second
	const pollInterval = 2 * time.Second

	config := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: hostKeyCallback,
		Timeout:         perDialTimeout,
	}

	var client *ssh.Client
	var lastErr error
	retryErr := wait.PollUntilContextTimeout(context.TODO(), pollInterval, overallTimeout, true, func(ctx context.Context) (bool, error) {
		c, dialErr := sshDial("tcp", addr, config)
		if dialErr == nil {
			client = c
			return true, nil
		}
		lastErr = dialErr
		if isPermanentSSHDialError(dialErr) {
			return false, dialErr
		}
		ginkgo.GinkgoLogr.Info("error dialing, retrying", "user", user, "addr", addr, "error", dialErr)
		return false, nil
	})
	if retryErr != nil {
		if lastErr != nil {
			return nil, fmt.Errorf("failed to initiate SSH connection to %s@%s: %w", user, addr, lastErr)
		}
		return nil, fmt.Errorf("failed to initiate SSH connection to %s@%s: %w", user, addr, retryErr)
	}
	return client, nil
}

func isPermanentSSHDialError(err error) bool {
	if err == nil {
		return false
	}
	var keyErr *knownhosts.KeyError
	if errors.As(err, &keyErr) && keyErr != nil {
		return true
	}
	if errors.Is(err, ssh.ErrNoAuth) {
		return true
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "unable to authenticate") {
		return true
	}
	if strings.Contains(msg, "host key") || strings.Contains(msg, "knownhosts") || strings.Contains(msg, "host key rejected") {
		return true
	}
	return false
}

func makePrivateKeySignerFromFile(key string) (ssh.Signer, error) {
	buffer, err := os.ReadFile(key)
	if err != nil {
		return nil, fmt.Errorf("error reading SSH key %s: %w", key, err)
	}
	signer, err := ssh.ParsePrivateKey(buffer)
	if err != nil {
		return nil, fmt.Errorf("error parsing SSH key: %w", err)
	}
	return signer, nil
}

// shellQuote wraps a string in single quotes and escapes existing single quotes
// so that it survives a shell evaluation as a single literal argument.
func shellQuote(s string) string {
	if len(s) == 0 {
		return "''"
	}
	// Replace ' with '\'' and wrap in ''
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}
