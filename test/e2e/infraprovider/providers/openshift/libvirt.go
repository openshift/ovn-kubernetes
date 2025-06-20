package openshift

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
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

type VM struct {
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

func addLibvirtMachine() (*machine, error) {
	cmd := exec.Command("bash", "-c", fmt.Sprintf(`
if kcli show vm %[1]s; then
  exit 0
fi
kcli create vm -i fedora41 %[1]s --wait -P cmds=['dnf install -y docker','systemctl enable --now docker']
`, testMachineSetName))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to start libvirt machine: %v, output: %s", err, string(output))
	}
	vm, err := showLibvirtVirtualMachine()
	if err != nil {
		return nil, fmt.Errorf("failed to show libvirt virtual machine after creation: %v", err)
	}
	m := &machine{
		name: vm.Name,
		ipv4: vm.IP,
		ipv6: vm.IPs[1],
	}
	return m, nil
}

func showLibvirtVirtualMachine() (*VM, error) {
	cmd := exec.Command("kcli", "show", "vm", testMachineSetName, "-o", "json")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to show libvirt virtual machine: %v, output: %s", err, string(output))
	}
	vm := &VM{}
	if err := json.Unmarshal(output, vm); err != nil {
		return nil, fmt.Errorf("failed to unmarshal libvirt virtual machine output: %v, output: %s", err, string(output))
	}
	return vm, nil
}

func delLibvirtMachine() error {
	cmd := exec.Command("kcli", "remove", "-y", "vm", testMachineSetName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to delete libvirt machine: %v, output: %s", err, string(output))
	}
	return nil
}

func (m *machine) libvirtExecCommand(cmd string) (result, error) {
	kcliSSHCmd := exec.Command("kcli", "ssh", "-t", testMachineSetName, "--", cmd)
	var stdout, stderr bytes.Buffer
	kcliSSHCmd.Stdout = &stdout
	kcliSSHCmd.Stderr = &stderr
	if err := kcliSSHCmd.Run(); err != nil {
		return result{cmd: cmd, stdout: stdout.String(), stderr: stderr.String()}, fmt.Errorf("failed to run command on libvirt machine: %w", err)
	}
	return result{cmd: cmd, stdout: stdout.String(), stderr: stderr.String()}, nil
}
