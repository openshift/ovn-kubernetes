package openshift

import (
	"encoding/json"
	"fmt"
	"os/exec"
)

const (
	testMachineName = "ovn-kubernetes-e2e"
)

type Net struct {
	Device string `json:"device"`
	Mac    string `json:"mac"`
	Net    string `json:"net"`
	Type   string `json:"type"`
}

type Disk struct {
	Device string `json:"device"`
	Size   int    `json:"size"`
	Format string `json:"format"`
	Type   string `json:"type"`
	Path   string `json:"path"`
}

type Machine struct {
	Name         string   `json:"name"`
	Nets         []Net    `json:"nets"`
	Disks        []Disk   `json:"disks"`
	ID           string   `json:"id"`
	User         string   `json:"user"`
	Image        string   `json:"image"`
	Plan         string   `json:"plan"`
	Profile      string   `json:"profile"`
	CreationDate string   `json:"creationdate"`
	IP           string   `json:"ip"`
	IPs          []string `json:"ips"`
	Status       string   `json:"status"`
	Autostart    bool     `json:"autostart"`
	NumCPUs      int      `json:"numcpus"`
	Memory       int      `json:"memory"`
}

func ensureTestMachine() (*machine, error) {
	cmd := exec.Command("bash", "-c", fmt.Sprintf(`
if kcli show vm %[1]s; then
  exit 0
fi
kcli create vm -i fedora41 %[1]s --wait -P cmds=['dnf install -y docker','systemctl enable --now docker']
`, testMachineName))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to start libvirt machine: %v, output: %s", err, string(output))
	}
	testMachine, err := showTestMachine()
	if err != nil {
		return nil, fmt.Errorf("failed to show libvirt virtual machine after creation: %v", err)
	}
	m := &machine{
		name: testMachine.Name,
		ipv4: testMachine.IP,
		ipv6: testMachine.IPs[1],
	}
	return m, nil
}

func showTestMachine() (*Machine, error) {
	return showMachine(testMachineName)
}

func showMachine(machineName string) (*Machine, error) {
	cmd := exec.Command("kcli", "show", "vm", machineName, "-o", "json")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to show libvirt virtual machine: %v, output: %s", err, string(output))
	}
	vm := &Machine{}
	if err := json.Unmarshal(output, vm); err != nil {
		return nil, fmt.Errorf("failed to unmarshal libvirt virtual machine output: %v, output: %s", err, string(output))
	}
	return vm, nil
}

func (m *Machine) findNetwork(networkName string) *Net {
	for _, machineNet := range m.Nets {
		if machineNet.Net == networkName {
			return &machineNet
		}
	}
	return nil
}

func (m *Machine) attachNetwork(networkName string) error {
	cmd := exec.Command("kcli", "add", "nic", m.Name, networkName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Errorf("%s: %w", string(output), err)
	}
	return nil
}
