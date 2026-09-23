package infraprovider

import (
	"testing"

	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/api"
)

// fakeRunner records the command and args passed to Run.
type fakeRunner struct {
	lastCommand string
	lastArgs    []string
}

func (f *fakeRunner) Run(command string, args ...string) (string, error) {
	f.lastCommand = command
	f.lastArgs = args
	return "", nil
}

func TestExtractDevFromRouteJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "valid route with dev",
			input: `[{"dst":"default","gateway":"10.0.0.1","dev":"eth0","protocol":"dhcp","metric":100}]`,
			want:  "eth0",
		},
		{
			name:  "empty routes",
			input: `[]`,
			want:  "",
		},
		{
			name:    "missing dev field",
			input:   `[{"dst":"default","gateway":"10.0.0.1"}]`,
			wantErr: true,
		},
		{
			name:    "malformed JSON",
			input:   `not json`,
			wantErr: true,
		},
		{
			name:  "multiple routes picks first",
			input: `[{"dev":"eth0","metric":100},{"dev":"eth1","metric":200}]`,
			want:  "eth0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractDevFromRouteJSON(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("extractDevFromRouteJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("extractDevFromRouteJSON() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseInterfaceAddresses(t *testing.T) {
	tests := []struct {
		name       string
		devName    string
		jsonStr    string
		wantIPv4   string
		wantIPv6   string
		wantPrefix string
		wantErr    bool
	}{
		{
			name:    "IPv4 only",
			devName: "eth0",
			jsonStr: `[{"ifname":"eth0","address":"aa:bb:cc:dd:ee:ff","addr_info":[{"family":"inet","local":"10.0.0.5","prefixlen":24}]}]`,
			wantIPv4: "10.0.0.5",
		},
		{
			name:    "IPv6 only (non-link-local)",
			devName: "eth0",
			jsonStr: `[{"ifname":"eth0","address":"aa:bb:cc:dd:ee:ff","addr_info":[{"family":"inet6","local":"2001:db8::1","prefixlen":64}]}]`,
			wantIPv6: "2001:db8::1",
		},
		{
			name:    "dual-stack",
			devName: "eth0",
			jsonStr: `[{"ifname":"eth0","address":"aa:bb:cc:dd:ee:ff","addr_info":[{"family":"inet","local":"10.0.0.5","prefixlen":24},{"family":"inet6","local":"2001:db8::1","prefixlen":64}]}]`,
			wantIPv4: "10.0.0.5",
			wantIPv6: "2001:db8::1",
		},
		{
			name:    "link-local IPv6 skipped",
			devName: "eth0",
			jsonStr: `[{"ifname":"eth0","address":"aa:bb:cc:dd:ee:ff","addr_info":[{"family":"inet6","local":"fe80::1","prefixlen":64},{"family":"inet6","local":"2001:db8::1","prefixlen":64}]}]`,
			wantIPv6: "2001:db8::1",
		},
		{
			name:    "only link-local IPv6",
			devName: "eth0",
			jsonStr: `[{"ifname":"eth0","address":"aa:bb:cc:dd:ee:ff","addr_info":[{"family":"inet6","local":"fe80::1","prefixlen":64}]}]`,
		},
		{
			name:    "empty addr_info",
			devName: "eth0",
			jsonStr: `[{"ifname":"eth0","address":"aa:bb:cc:dd:ee:ff","addr_info":[]}]`,
		},
		{
			name:    "empty links array",
			devName: "eth0",
			jsonStr: `[]`,
			wantErr: true,
		},
		{
			name:    "malformed JSON",
			devName: "eth0",
			jsonStr: `{invalid`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseInterfaceAddresses(tt.devName, tt.jsonStr)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseInterfaceAddresses() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got.IPv4 != tt.wantIPv4 {
				t.Errorf("IPv4 = %q, want %q", got.IPv4, tt.wantIPv4)
			}
			if got.IPv6 != tt.wantIPv6 {
				t.Errorf("IPv6 = %q, want %q", got.IPv6, tt.wantIPv6)
			}
			if got.InfName != tt.devName {
				t.Errorf("InfName = %q, want %q", got.InfName, tt.devName)
			}
		})
	}
}

func TestBuildMachineNetwork(t *testing.T) {
	tests := []struct {
		name    string
		netName string
		netInfo *api.NetworkInterface
		wantErr bool
	}{
		{
			name:    "nil netInfo",
			netName: "host",
			netInfo: nil,
			wantErr: true,
		},
		{
			name:    "IPv4 only",
			netName: "host",
			netInfo: &api.NetworkInterface{IPv4Prefix: "10.0.0.0/24"},
		},
		{
			name:    "IPv6 only",
			netName: "host",
			netInfo: &api.NetworkInterface{IPv6Prefix: "2001:db8::/64"},
		},
		{
			name:    "dual-stack",
			netName: "host",
			netInfo: &api.NetworkInterface{IPv4Prefix: "10.0.0.0/24", IPv6Prefix: "2001:db8::/64"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			net, err := buildMachineNetwork(tt.netName, tt.netInfo)
			if (err != nil) != tt.wantErr {
				t.Fatalf("buildMachineNetwork() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if net == nil {
				t.Fatal("buildMachineNetwork() returned nil network")
			}
			if net.Name() != tt.netName {
				t.Errorf("Name() = %q, want %q", net.Name(), tt.netName)
			}
		})
	}
}

func TestSudoRunner(t *testing.T) {
	inner := &fakeRunner{}
	sr := &sudoRunner{inner: inner}

	_, _ = sr.Run("podman", "run", "--name", "test")

	if inner.lastCommand != "sudo" {
		t.Errorf("expected command %q, got %q", "sudo", inner.lastCommand)
	}
	wantArgs := []string{"podman", "run", "--name", "test"}
	if len(inner.lastArgs) != len(wantArgs) {
		t.Fatalf("expected %d args, got %d", len(wantArgs), len(inner.lastArgs))
	}
	for i, a := range wantArgs {
		if inner.lastArgs[i] != a {
			t.Errorf("arg[%d] = %q, want %q", i, inner.lastArgs[i], a)
		}
	}
}

func TestInfrastructureNetworkExclusions(t *testing.T) {
	tests := []struct {
		name          string
		hostNetInfo   *api.NetworkInterface
		wantV4Count   int
		wantV6Count   int
		wantV4Contains string
		wantV6Contains string
	}{
		{
			name:        "nil hostNetworkInfo",
			hostNetInfo: nil,
			wantV4Count: 0,
			wantV6Count: 0,
		},
		{
			name:           "IPv4 only",
			hostNetInfo:    &api.NetworkInterface{IPv4Prefix: "10.0.0.5/24"},
			wantV4Count:    1,
			wantV6Count:    0,
			wantV4Contains: "10.0.0.0/24",
		},
		{
			name:           "IPv6 only",
			hostNetInfo:    &api.NetworkInterface{IPv6Prefix: "2001:db8::1/64"},
			wantV4Count:    0,
			wantV6Count:    1,
			wantV6Contains: "2001:db8::/64",
		},
		{
			name:           "dual-stack",
			hostNetInfo:    &api.NetworkInterface{IPv4Prefix: "192.168.1.10/16", IPv6Prefix: "fd00::5/120"},
			wantV4Count:    1,
			wantV6Count:    1,
			wantV4Contains: "192.168.0.0/16",
			wantV6Contains: "fd00::/120",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &baseInfra{hostNetworkInfo: tt.hostNetInfo}
			ipv4, ipv6 := b.InfrastructureNetworkExclusions()
			if ipv4.Len() != tt.wantV4Count {
				t.Errorf("IPv4 set length = %d, want %d", ipv4.Len(), tt.wantV4Count)
			}
			if ipv6.Len() != tt.wantV6Count {
				t.Errorf("IPv6 set length = %d, want %d", ipv6.Len(), tt.wantV6Count)
			}
			if tt.wantV4Contains != "" && !ipv4.Has(tt.wantV4Contains) {
				t.Errorf("IPv4 set should contain %q, got %v", tt.wantV4Contains, ipv4.UnsortedList())
			}
			if tt.wantV6Contains != "" && !ipv6.Has(tt.wantV6Contains) {
				t.Errorf("IPv6 set should contain %q, got %v", tt.wantV6Contains, ipv6.UnsortedList())
			}
		})
	}
}
