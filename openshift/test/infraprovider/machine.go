package infraprovider

import (
	"fmt"
	"os"
)

const (
	vmIPEnvKey              = "VM_IP"
	hypervisorIPEnvKey      = "HYPERVISOR_IP"
	testMachineName         = "ovn-kubernetes-e2e"
	hypervisorKeyPathEnvKey = "HYPERVISOR_SSH_KEY"
	vmKeyPathEnvKey         = "VM_SSH_KEY"
)

func ensureTestMachine() (*machine, error) {
	hypervisorIP := os.Getenv(hypervisorIPEnvKey)
	if len(hypervisorIP) == 0 {
		return nil, fmt.Errorf("no hypervisor found for test machine")
	}
	machineIP := os.Getenv(vmIPEnvKey)
	if len(machineIP) == 0 {
		return nil, fmt.Errorf("machine IP is not found for test machine")
	}
	signerForHypervisor, err := getSigner(hypervisorKeyPathEnvKey)
	if err != nil {
		return nil, fmt.Errorf("error getting ssh proxy signer: %w", err)
	}
	signerForMachine, err := getSigner(vmKeyPathEnvKey)
	if err != nil {
		return nil, fmt.Errorf("error getting ssh machine signer: %w", err)
	}
	m := &machine{name: testMachineName,
		proxyIP:        hypervisorIP,
		defaultIP:      machineIP,
		proxySshSigner: signerForHypervisor,
		sshSigner:      signerForMachine,
	}
	return m, nil
}
