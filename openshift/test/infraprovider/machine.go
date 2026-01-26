package infraprovider

import (
	"encoding/json"
	"fmt"
	"net"
	"os/exec"

	utilnet "k8s.io/utils/net"
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

func ensureTestMachine(machineName string) (*machine, error) {
	// Check if machine already exists
	checkCmd := exec.Command("kcli", "show", "vm", machineName)
	if err := checkCmd.Run(); err != nil {
		// Machine doesn't exist, create it
		createCmd := exec.Command("kcli", "create", "vm", "-i", "fedora42", machineName, "--wait",
			"-P", "cmds=['dnf install -y docker','systemctl enable --now docker']")
		output, err := createCmd.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("failed to create libvirt machine: %v, output: %s", err, string(output))
		}
	}
	// Retrieve machine information (whether it existed or was just created)
	testMachine, err := showMachine(machineName)
	if err != nil {
		return nil, fmt.Errorf("failed to show libvirt virtual machine %s, err: %w", machineName, err)
	}
	if len(testMachine.Nets) == 0 {
		return nil, fmt.Errorf("no networks configured for libvirt virtual machine %s", machineName)
	}
	m := &machine{
		name:          testMachine.Name,
		ipv4Addresses: map[string]string{},
		ipv6Addresses: map[string]string{},
	}
	for _, net := range testMachine.Nets {
		network, err := getNetwork(net.Net)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve network %s, err: %w", net.Net, err)
		}
		ips := append([]string{}, testMachine.IPs...)
		ips = append(ips, testMachine.IP)
		for _, ip := range ips {
			in, err := ipInCIDR(ip, network.CIDR)
			if err != nil {
				return nil, fmt.Errorf("error while checking machine %s IP address with network %s CIDR, err: %w",
					machineName, net.Net, err)
			}
			if in && utilnet.IsIPv4String(ip) {
				m.ipv4Addresses[net.Net] = ip
			} else if in {
				m.ipv6Addresses[net.Net] = ip
			}
		}
	}
	return m, nil
}

func showMachine(machineName string) (*Machine, error) {
	cmd := exec.Command("kcli", "show", "vm", machineName, "-o", "json")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to show libvirt virtual machine %s, output: %s, err: %w", machineName, string(output), err)
	}
	vm := &Machine{}
	if err := json.Unmarshal(output, vm); err != nil {
		return nil, fmt.Errorf("failed to unmarshal libvirt virtual machine %s, output: %s, err: %w", machineName, string(output), err)
	}
	return vm, nil
}

func removeMachine(machineName string) error {
	cmd := exec.Command("kcli", "remove", "-y", "vm", machineName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to delete libvirt machine: %s, output: %s, err: %w", machineName, string(output), err)
	}
	return nil
}

func (m *Machine) attachNetwork(networkName string) error {
	cmd := exec.Command("kcli", "add", "nic", m.Name, "-n", networkName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf(
			"failed to attach network %s to machine %s, output: %s, err: %w",
			networkName,
			m.Name,
			string(output),
			err)
	}
	return nil
}

func (m *Machine) detachNetwork(networkName, interfaceName string) error {
	cmd := exec.Command("kcli", "remove", "nic", "-y", m.Name, "-n", networkName, "-i", interfaceName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf(
			"failed to detach network %s from machine %s, output: %s, err: %w",
			networkName,
			m.Name,
			string(output),
			err)
	}
	return nil
}

func ipInCIDR(ipStr, cidrStr string) (bool, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, fmt.Errorf("invalid IP address: %q", ipStr)
	}
	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return false, err
	}
	return ipNet.Contains(ip), nil
}

func isKcliInstalled() bool {
	_, err := exec.LookPath("kcli")
	return err == nil
}
