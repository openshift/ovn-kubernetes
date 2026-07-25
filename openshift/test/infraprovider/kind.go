package infraprovider

import (
	"fmt"
	"os"

	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/api"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/runner"
	infraproviderkind "github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/providers/kind"
)

const (
	kindHostUser      = "root"
	kindHostSshport   = "22"
	envKindHost       = "KIND_HOST"
	envKindHostSSHKey = "KIND_HOST_SSH_KEY"
)

// InitializeKindInfra initializes a kind infrastructure provider with SSH-based command execution.
// Used when OTE binary runs in a container and needs to interact with a kind cluster on a remote host.
// Requires KIND_HOST, KIND_HOST_SSH_KEY, and CONTAINER_RUNTIME environment variables.
func InitializeKindInfra() (api.Provider, error) {
	// Initialize command runner for executing commands on the host
	ce := infraproviderkind.GetContainerRuntime()
	sshRunner, err := hostSshCmdRunner()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize SSH runner: %w", err)
	}

	// Validate SSH connectivity before proceeding
	if err := validateSSHConnection(sshRunner); err != nil {
		return nil, fmt.Errorf("SSH connection validation failed: %w", err)
	}

	return infraproviderkind.New(ce, sshRunner), nil
}

func hostSshCmdRunner() (api.Runner, error) {
	// Read host IP from env variable
	ip := os.Getenv(envKindHost)
	if ip == "" {
		return nil, fmt.Errorf("%s environment variable is not set", envKindHost)
	}

	// Find SSH key for host access
	sshKeyPath, err := findKindHostSSHKeyPath()
	if err != nil {
		return nil, fmt.Errorf("SSH key configuration failed: %w", err)
	}

	sshRunner, err := runner.NewSSHRunner(ip, kindHostUser, kindHostSshport, sshKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH runner for kind host: %w", err)
	}

	return sshRunner, nil
}

// findKindHostSSHKeyPath locates the SSH private key file for host access.
func findKindHostSSHKeyPath() (string, error) {
	sshKeyPath := os.Getenv(envKindHostSSHKey)
	if sshKeyPath == "" {
		return "", fmt.Errorf("%s environment variable is not set", envKindHostSSHKey)
	}

	exists, err := fileExists(sshKeyPath)
	if err != nil {
		return "", fmt.Errorf("failed to check SSH key file %q: %w", sshKeyPath, err)
	}
	if !exists {
		return "", fmt.Errorf("SSH key file %q does not exist", sshKeyPath)
	}

	return sshKeyPath, nil
}

// validateSSHConnection tests if the SSH runner can successfully execute commands.
func validateSSHConnection(runner api.Runner) error {
	// Quick connectivity test
	_, err := runner.Run("echo", "test")
	if err != nil {
		return fmt.Errorf("cannot execute commands on kind host: %w", err)
	}
	return nil
}
