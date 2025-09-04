package openshift

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
	"k8s.io/apimachinery/pkg/util/wait"
)

const sshKeyPathEnvKey = "SSH_KEY_PATH" //TODO: check if theres ocp env var already

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

func (r result) getStdOut() string {
	return r.stdout
}

// runSSHCommandViaBastion returns the stdout, stderr, and exit code from running cmd on
// host as specific user, along with any SSH-level error.
func runSSHCommand(cmd, addr string, signer ssh.Signer) (result, error) {
	result := result{}
	config := &ssh.ClientConfig{
		User:            machineUserName,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		err = wait.PollUntilContextTimeout(context.TODO(), 5*time.Second, 20*time.Second, true, func(ctx context.Context) (bool, error) {
			fmt.Printf("error dialing %s@%s: %v, retrying\n", machineUserName, addr, err)
			if client, err = ssh.Dial("tcp", addr, config); err != nil {
				return false, nil
			}
			return true, nil
		})
	}
	if err != nil {
		return result, fmt.Errorf("failed to initiate SSH connection to %s@%s: %v", machineUserName, addr, err)
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return result, fmt.Errorf("failed creating new session to %s@%s: %w", machineUserName, addr, err)
	}
	defer session.Close()

	// Run the command.
	var bout, berr bytes.Buffer
	session.Stdout, session.Stderr = &bout, &berr
	if err = session.Run(cmd); err != nil {
		err = fmt.Errorf("failed running `%s` on %s@%s: %w", cmd, machineUserName, addr, err)
	}
	result.cmd = cmd
	result.stdout = bout.String()
	result.stderr = berr.String()
	result.user = machineUserName
	result.ip = addr
	return result, err
}

func getSigner() (ssh.Signer, error) {
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
