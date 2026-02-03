package infraprovider

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
	"k8s.io/apimachinery/pkg/util/wait"
)

// runSSHCommand returns the stdout, stderr, and exit code from running cmd on
// host as specific user, along with any SSH-level error.
func runSSHCommand(user, cmd string, proxyClient *ssh.Client, addr string, signer ssh.Signer) (result, error) {
	res := result{}
	targetConn, err := proxyClient.Dial("tcp", addr)
	if err != nil {
		err = wait.PollUntilContextTimeout(context.TODO(), 5*time.Second, 20*time.Second, true, func(ctx context.Context) (bool, error) {
			var dialErr error
			targetConn, dialErr = proxyClient.Dial("tcp", addr)
			if dialErr != nil {
				fmt.Printf("error dialing %s: %v, retrying\n", addr, dialErr)
				return false, nil
			}
			return true, nil
		})
	}
	if err != nil {
		return res, fmt.Errorf("failed to initiate SSH connection to %s: %v", addr, err)
	}
	defer targetConn.Close()
	targetConfig := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	conn, chans, reqs, err := ssh.NewClientConn(targetConn, addr, targetConfig)
	if err != nil {
		return res, fmt.Errorf("ssh handshake failed for address %s: %w", addr, err)
	}
	defer conn.Close()

	targetClient := ssh.NewClient(conn, chans, reqs)
	defer targetClient.Close()
	session, err := targetClient.NewSession()
	if err != nil {
		return res, fmt.Errorf("failed creating new session to %s@%s: %w", user, addr, err)
	}
	defer session.Close()

	// Run the command.
	var bout, berr bytes.Buffer
	session.Stdout, session.Stderr = &bout, &berr
	if err = session.Run(cmd); err != nil {
		err = fmt.Errorf("failed running `%s` on %s@%s: %w", cmd, user, addr, err)
	}
	res.cmd = cmd
	res.stdout = bout.String()
	res.stderr = berr.String()
	res.user = user
	res.ip = addr
	return res, err
}

func getSshClient(user, addr string, signer ssh.Signer) (*ssh.Client, error) {
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		// NOTE: InsecureIgnoreHostKey is used here because this is a test environment
		// where we're connecting to ephemeral VMs. In production, use proper host key verification.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		err = wait.PollUntilContextTimeout(context.TODO(), 5*time.Second, 20*time.Second, true, func(ctx context.Context) (bool, error) {
			var dialErr error
			client, dialErr = ssh.Dial("tcp", addr, config)
			if dialErr != nil {
				fmt.Printf("error dialing %s@%s: %v, retrying\n", user, addr, dialErr)
				return false, nil
			}
			return true, nil
		})
	}
	if err != nil {
		return nil, fmt.Errorf("failed to initiate SSH connection to %s@%s: %v", user, addr, err)
	}
	return client, nil
}

func getSigner(sshKeyPathEnvKey string) (ssh.Signer, error) {
	if path := os.Getenv(sshKeyPathEnvKey); len(path) > 0 {
		return makePrivateKeySignerFromFile(path)
	}
	return nil, fmt.Errorf("environment key %q is not set or doesn't have a valid value", sshKeyPathEnvKey)
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
	return signer, err
}
