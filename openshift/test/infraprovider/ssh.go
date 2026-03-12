package infraprovider

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"time"

	"github.com/onsi/ginkgo/v2"
	"golang.org/x/crypto/ssh"
	"k8s.io/apimachinery/pkg/util/wait"
)

// runSSHCommand returns the stdout, stderr, and exit code from running cmd on
// host as specific user, along with any SSH-level error.
func runSSHCommand(sshClient *ssh.Client, cmd string) (result, error) {
	res := result{}
	user := sshClient.User()
	addr := sshClient.RemoteAddr().String()
	session, err := sshClient.NewSession()
	if err != nil {
		return res, fmt.Errorf("failed creating new ssh session with %s@%s: %w", user, addr, err)
	}
	defer session.Close()

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
				ginkgo.GinkgoLogr.Info("error dialing, retrying", "user", user, "addr", addr, "error", dialErr)
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
