package infraprovider

import (
	"fmt"
	"strings"

	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider"
)

// hypervisorCommandRunner executes podman commands on a remote hypervisor via SSH
type hypervisorCommandRunner struct {
	hypervisor *hypervisor
}

// NewHypervisorCommandRunner creates a command runner that executes commands
// on a remote hypervisor via SSH
func NewHypervisorCommandRunner(h *hypervisor) infraprovider.CommandRunner {
	return &hypervisorCommandRunner{
		hypervisor: h,
	}
}

func (r *hypervisorCommandRunner) Run(args ...string) (string, error) {
	// Build the command string (e.g., "podman network inspect kind")
	var cmdParts []string
	cmdParts = append(cmdParts, "podman")
	cmdParts = append(cmdParts, args...)
	cmd := strings.Join(cmdParts, " ")

	// Add elevated privileges for podman commands
	cmd = addElevatedPrivileges(cmd)

	if r.hypervisor == nil {
		return "", fmt.Errorf("hypervisor is not set, cannot run the command %s", cmd)
	}

	// Execute via SSH on the hypervisor
	result, err := r.hypervisor.execCmd(cmd)
	if err != nil {
		return "", fmt.Errorf("command failed: %w, output: %s", err, result.stdout)
	}
	return result.stdout, nil
}
