// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package infraprovider

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/api"
)

func TestIpInCIDR(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		cidr    string
		want    bool
		wantErr bool
	}{
		{
			name: "IPv4 in range",
			ip:   "192.168.1.10",
			cidr: "192.168.1.0/24",
			want: true,
		},
		{
			name: "IPv4 out of range",
			ip:   "10.0.0.1",
			cidr: "192.168.1.0/24",
			want: false,
		},
		{
			name: "IPv6 in range",
			ip:   "2001:db8::5",
			cidr: "2001:db8::/64",
			want: true,
		},
		{
			name: "IPv6 out of range",
			ip:   "2001:db9::1",
			cidr: "2001:db8::/64",
			want: false,
		},
		{
			name:    "invalid IP",
			ip:      "not-an-ip",
			cidr:    "192.168.1.0/24",
			wantErr: true,
		},
		{
			name:    "invalid CIDR",
			ip:      "192.168.1.1",
			cidr:    "not-a-cidr",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ipInCIDR(tt.ip, tt.cidr)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ipInCIDR() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("ipInCIDR(%q, %q) = %v, want %v", tt.ip, tt.cidr, got, tt.want)
			}
		})
	}
}

func TestFindInterfaceBySubnet(t *testing.T) {
	tests := []struct {
		name      string
		json      string
		v4Subnet  string
		v6Subnet  string
		want      string
		wantError bool
	}{
		{
			name: "match on v4 subnet",
			json: `[{"ifname":"ens3","address":"aa:bb:cc:dd:ee:ff","addr_info":[
				{"family":"inet","local":"192.168.111.10","prefixlen":24}
			]}]`,
			v4Subnet: "192.168.111.0/24",
			want:     "ens3",
		},
		{
			name: "match on v6 subnet",
			json: `[{"ifname":"ens4","address":"aa:bb:cc:dd:ee:ff","addr_info":[
				{"family":"inet6","local":"fd2e:6f44:5dd8:c956::10","prefixlen":64}
			]}]`,
			v6Subnet: "fd2e:6f44:5dd8:c956::/64",
			want:     "ens4",
		},
		{
			name: "no match",
			json: `[{"ifname":"lo","address":"00:00:00:00:00:00","addr_info":[
				{"family":"inet","local":"127.0.0.1","prefixlen":8}
			]}]`,
			v4Subnet: "192.168.111.0/24",
			want:     "",
		},
		{
			name:      "malformed JSON",
			json:      `{invalid`,
			v4Subnet:  "192.168.111.0/24",
			wantError: true,
		},
		{
			name: "multiple interfaces, second matches",
			json: `[
				{"ifname":"lo","address":"00:00:00:00:00:00","addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8}]},
				{"ifname":"ens3","address":"aa:bb:cc:dd:ee:ff","addr_info":[{"family":"inet","local":"10.10.10.5","prefixlen":24}]}
			]`,
			v4Subnet: "10.10.10.0/24",
			want:     "ens3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := findInterfaceBySubnet(tt.json, tt.v4Subnet, tt.v6Subnet)
			if tt.wantError {
				if err == nil {
					t.Errorf("findInterfaceBySubnet() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("findInterfaceBySubnet() unexpected error: %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("findInterfaceBySubnet() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTryMatchLink(t *testing.T) {
	tests := []struct {
		name     string
		link     linkInfo
		v4Subnet string
		v6Subnet string
		wantNil  bool
		wantIPv4 string
		wantIPv6 string
	}{
		{
			name: "v4-only match",
			link: linkInfo{
				IfName: "ens3",
				Mac:    "aa:bb:cc:dd:ee:ff",
				AddrInfo: []ipAddressInfo{
					{Family: "inet", Local: "192.168.111.10", PrefixLen: 24},
				},
			},
			v4Subnet: "192.168.111.0/24",
			wantIPv4: "192.168.111.10",
		},
		{
			name: "v6-only match",
			link: linkInfo{
				IfName: "ens3",
				Mac:    "aa:bb:cc:dd:ee:ff",
				AddrInfo: []ipAddressInfo{
					{Family: "inet6", Local: "fd2e:6f44:5dd8:c956::10", PrefixLen: 64},
				},
			},
			v6Subnet: "fd2e:6f44:5dd8:c956::/64",
			wantIPv6: "fd2e:6f44:5dd8:c956::10",
		},
		{
			name: "dual-stack match",
			link: linkInfo{
				IfName: "ens3",
				Mac:    "aa:bb:cc:dd:ee:ff",
				AddrInfo: []ipAddressInfo{
					{Family: "inet", Local: "192.168.111.10", PrefixLen: 24},
					{Family: "inet6", Local: "fd2e:6f44:5dd8:c956::10", PrefixLen: 64},
				},
			},
			v4Subnet: "192.168.111.0/24",
			v6Subnet: "fd2e:6f44:5dd8:c956::/64",
			wantIPv4: "192.168.111.10",
			wantIPv6: "fd2e:6f44:5dd8:c956::10",
		},
		{
			name: "partial match - only v4 when both required",
			link: linkInfo{
				IfName: "ens3",
				Mac:    "aa:bb:cc:dd:ee:ff",
				AddrInfo: []ipAddressInfo{
					{Family: "inet", Local: "192.168.111.10", PrefixLen: 24},
				},
			},
			v4Subnet: "192.168.111.0/24",
			v6Subnet: "fd2e:6f44:5dd8:c956::/64",
			wantNil:  true,
		},
		{
			name: "no match",
			link: linkInfo{
				IfName: "lo",
				Mac:    "00:00:00:00:00:00",
				AddrInfo: []ipAddressInfo{
					{Family: "inet", Local: "127.0.0.1", PrefixLen: 8},
				},
			},
			v4Subnet: "192.168.111.0/24",
			wantNil:  true,
		},
		{
			name: "empty addr_info",
			link: linkInfo{
				IfName:   "ens3",
				Mac:      "aa:bb:cc:dd:ee:ff",
				AddrInfo: nil,
			},
			v4Subnet: "192.168.111.0/24",
			wantNil:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tryMatchLink(tt.link, tt.v4Subnet, tt.v6Subnet)
			if tt.wantNil {
				if got != nil {
					t.Fatalf("tryMatchLink() = %+v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatal("tryMatchLink() = nil, want non-nil")
				return
			}
			if got.IPv4 != tt.wantIPv4 {
				t.Errorf("IPv4 = %q, want %q", got.IPv4, tt.wantIPv4)
			}
			if got.IPv6 != tt.wantIPv6 {
				t.Errorf("IPv6 = %q, want %q", got.IPv6, tt.wantIPv6)
			}
		})
	}
}

func TestReservedExGwIPAM(t *testing.T) {
	tests := []struct {
		name       string
		subnet     string
		wantGW     string
		wantRange  string
		wantPrefix int
		wantErr    bool
	}{
		{
			name:       "IPv4 /24",
			subnet:     "192.168.111.0/24",
			wantGW:     "192.168.111.239",
			wantRange:  "192.168.111.240/28",
			wantPrefix: 24,
		},
		{
			name:       "IPv6 /64",
			subnet:     "fd2e:6f44:5dd8:c956::/64",
			wantGW:     "fd2e:6f44:5dd8:c956:ffff:ffff:ffff:ffef",
			wantRange:  "fd2e:6f44:5dd8:c956:ffff:ffff:ffff:fff0/124",
			wantPrefix: 64,
		},
		{
			// Metal dualstack MachineNetworks IPv6 is typically /120.
			name:       "IPv6 /120 metal machine network",
			subnet:     "fd2e:6f44:5dd8:c956::/120",
			wantGW:     "fd2e:6f44:5dd8:c956::ef",
			wantRange:  "fd2e:6f44:5dd8:c956::f0/124",
			wantPrefix: 120,
		},
		{
			name:    "IPv4 too small",
			subnet:  "192.168.111.0/28",
			wantErr: true,
		},
		{
			name:    "invalid subnet",
			subnet:  "not-a-cidr",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := reservedExGwIPAM(tt.subnet)
			if (err != nil) != tt.wantErr {
				t.Fatalf("reservedExGwIPAM() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got.Gateway != tt.wantGW || got.IPRange != tt.wantRange || got.SubnetPrefix != tt.wantPrefix {
				t.Errorf("reservedExGwIPAM(%q) = %+v, want gw=%s range=%s prefix=%d",
					tt.subnet, got, tt.wantGW, tt.wantRange, tt.wantPrefix)
			}
		})
	}
}

type egMockAddr struct {
	Family    string `json:"family"`
	Local     string `json:"local"`
	PrefixLen int    `json:"prefixlen"`
}

type egProbeError int

func (e egProbeError) Error() string   { return fmt.Sprintf("podman exited %d", e) }
func (e egProbeError) ExitStatus() int { return int(e) }

// egNetRunner records hypervisor commands for ensureExternalGatewayNetwork.
type egNetRunner struct {
	networkExists    bool
	probeErr         error
	routes4, routes6 string
	linkExists       bool
	cmds             []string
	createCmd        string
	createArgs       []string
	attached         string
	parentIndex      int
	removed          bool
	// addrs is returned (and mutated) for "ip -j addr show" / "ip addr del".
	addrs []egMockAddr
}

func (r *egNetRunner) addrShowJSON() string {
	type wrap struct {
		AddrInfo []egMockAddr `json:"addr_info"`
	}
	b, _ := json.Marshal([]wrap{{AddrInfo: r.addrs}})
	return string(b)
}

func (r *egNetRunner) Run(command string, args ...string) (string, error) {
	joined := strings.Join(append([]string{command}, args...), " ")
	r.cmds = append(r.cmds, joined)

	switch {
	case command == "podman" && len(args) >= 2 && args[0] == "network" && args[1] == "exists":
		if r.probeErr != nil {
			return "", r.probeErr
		}
		if r.networkExists {
			return "", nil
		}
		return "", egProbeError(1)
	case command == "podman" && len(args) > 0 && args[0] == "ps":
		return r.attached, nil
	case command == "podman" && len(args) >= 2 && args[0] == "network" && args[1] == "rm":
		r.removed = true
		r.networkExists = false
		return "", nil
	case command == "podman" && len(args) >= 2 && args[0] == "network" && args[1] == "create":
		if r.networkExists {
			return "", errors.New("old network still exists")
		}
		r.createCmd = joined
		r.createArgs = append([]string(nil), args...)
		return "", nil
	case command == "ip" && len(args) >= 3 && args[0] == "link" && args[1] == "show":
		if r.linkExists {
			return "", nil
		}
		return "", egProbeError(1)
	case command == "ip" && len(args) >= 4 && args[0] == "-j" && args[1] == "-d":
		index := r.parentIndex
		if index == 0 {
			return `[{"link":"baremetal","linkinfo":{"info_kind":"macvlan","info_data":{"mode":"bridge"}}}]`, nil
		}
		return fmt.Sprintf(`[{"link_index":%d,"linkinfo":{"info_kind":"macvlan","info_data":{"mode":"bridge"}}}]`, index), nil
	case command == "ip" && len(args) >= 4 && args[0] == "-j" && args[1] == "link":
		return `[{"ifindex":2}]`, nil
	case command == "ip" && len(args) >= 4 && args[0] == "-j" && args[1] == "addr" && args[2] == "show":
		if args[len(args)-1] != bmExGwHostLinkName {
			return `[{"addr_info":[{"local":"192.168.111.1","prefixlen":24},{"local":"fd2e:6f44:5dd8:c956::1","prefixlen":120}]}]`, nil
		}
		return r.addrShowJSON(), nil
	case command == "ip" && len(args) >= 5 && args[0] == "addr" && args[1] == "del":
		ip, ipNet, err := net.ParseCIDR(args[2])
		if err == nil {
			prefix, _ := ipNet.Mask.Size()
			kept := r.addrs[:0]
			for _, a := range r.addrs {
				existing := net.ParseIP(a.Local)
				if existing != nil && existing.Equal(ip) && a.PrefixLen == prefix {
					continue
				}
				kept = append(kept, a)
			}
			r.addrs = kept
		}
		return "", nil
	case command == "ip" && strings.Contains(" "+strings.Join(args, " ")+" ", " -j route show "):
		out := r.routes4
		if args[0] == "-6" {
			out = r.routes6
		}
		if out == "" {
			out = "[]"
		}
		return out, nil
	case command == "ip" && len(args) >= 2 && args[len(args)-2] == "route" && args[len(args)-1] == "default":
		return `[{"dst":"default","gateway":"192.168.111.254","dev":"baremetal"}]`, nil
	case command == "firewall-cmd" && len(args) >= 1 && args[len(args)-1] == "--get-policies":
		return exGwFirewallPolicy, nil
	case command == "firewall-cmd" && len(args) >= 1 && args[0] == "--state":
		return "running", nil
	case command == "firewall-cmd" && len(args) >= 1 && strings.HasPrefix(args[0], "--get-zone-of-interface="):
		return "public", nil
	case command == "iptables" || command == "ip6tables":
		if len(args) >= 1 && (args[0] == "-C" || (len(args) >= 3 && args[2] == "-C")) {
			return "", errors.New("Bad rule")
		}
		return "", nil
	default:
		// ip link add/set, ip addr add, sysctl, firewall-cmd mutations succeed.
		return "", nil
	}
}

func TestEnsureExternalGatewayNetwork(t *testing.T) {
	hostNet := &api.NetworkInterface{
		InfName: "baremetal",
		IPv4:    "192.168.111.1",
		IPv6:    "fd2e:6f44:5dd8:c956::1",
	}

	t.Run("recreates existing network with sibling gateway", func(t *testing.T) {
		r := &egNetRunner{networkExists: true}
		if err := ensureExternalGatewayNetwork(r, hostNet, "192.168.111.0/24", "fd2e:6f44:5dd8:c956::/120"); err != nil {
			t.Fatalf("ensureExternalGatewayNetwork() error = %v", err)
		}
		if !r.removed {
			t.Fatal("expected existing network to be removed before recreate")
		}
		if r.createCmd == "" {
			t.Fatal("expected network create after remove")
		}
	})

	t.Run("reports attached containers before changing host networking", func(t *testing.T) {
		r := &egNetRunner{networkExists: true, attached: "leftover-gateway"}
		err := ensureExternalGatewayNetwork(r, hostNet, "192.168.111.0/24", "fd2e:6f44:5dd8:c956::/120")
		if err == nil || !strings.Contains(err.Error(), r.attached) {
			t.Fatalf("expected named attachment error, got %v", err)
		}
		want := []string{
			"podman network exists xgw",
			"ip -j addr show dev baremetal",
			"podman ps -a --filter network=xgw --format {{.Names}}",
		}
		if !reflect.DeepEqual(r.cmds, want) {
			t.Fatalf("attached network must allow only read-only checks: got %q, want %q", r.cmds, want)
		}
	})
	t.Run("rejects sibling on a different uplink", func(t *testing.T) {
		r := &egNetRunner{linkExists: true, parentIndex: 9}
		err := ensureExternalGatewayNetwork(r, hostNet, "192.168.111.0/24", "fd2e:6f44:5dd8:c956::/120")
		if err == nil || !strings.Contains(err.Error(), "stale test interface") {
			t.Fatalf("expected sibling mismatch, got %v", err)
		}
		if strings.Contains(strings.Join(r.cmds, "\n"), "ip addr add") {
			t.Fatal("must not change addresses on the wrong sibling")
		}
	})

	t.Run("operational probe failure leaves host state untouched", func(t *testing.T) {
		r := &egNetRunner{probeErr: egProbeError(125)}
		err := ensureExternalGatewayNetwork(r, hostNet, "192.168.111.0/24", "fd2e:6f44:5dd8:c956::/120")
		if err == nil || !strings.Contains(err.Error(), "probe xgw") {
			t.Fatalf("expected network probe error, got %v", err)
		}
		if len(r.cmds) != 1 {
			t.Fatalf("probe failure must not change host state: %v", r.cmds)
		}
	})
	t.Run("reconciles a previous IPv6 pool on the test sibling", func(t *testing.T) {
		r := &egNetRunner{linkExists: true, addrs: []egMockAddr{{Family: "inet6", Local: "fd2e:6f44:5dd8:c956::ef", PrefixLen: 128}}, routes6: `[{"dst":"fd2e:6f44:5dd8:c956::f0/124","protocol":"boot"}]`}
		if err := ensureExternalGatewayNetwork(r, hostNet, "192.168.111.0/24", "fd2e:6f44:5dd8:c956::/64"); err != nil {
			t.Fatalf("ensureExternalGatewayNetwork() failed: %v", err)
		}
		all := strings.Join(r.cmds, "\n")
		for _, want := range []string{"ip addr del fd2e:6f44:5dd8:c956::ef/128 dev xgw-host", "ip -6 route del fd2e:6f44:5dd8:c956::f0/124 dev xgw-host", "ip addr add fd2e:6f44:5dd8:c956:ffff:ffff:ffff:ffef/128 dev xgw-host nodad"} {
			if !strings.Contains(all, want) {
				t.Errorf("missing pool reconciliation command %q", want)
			}
		}
	})

	t.Run("IPv6-only pools clear owned IPv4 rules without enabling forwarding", func(t *testing.T) {
		r := &egNetRunner{}
		if err := ensureExternalGatewayNetwork(r, hostNet, "", "fd2e:6f44:5dd8:c956::/120"); err != nil {
			t.Fatalf("ensureExternalGatewayNetwork() failed: %v", err)
		}
		all := strings.Join(r.cmds, "\n")
		for _, want := range []string{"iptables -t nat -F OVN-EXGW-NAT", "iptables -t filter -F OVN-EXGW-FWD"} {
			if !strings.Contains(all, want) {
				t.Errorf("missing cleanup for removed IPv4 pool: %s", want)
			}
		}
		for _, unexpected := range []string{"net.ipv4.ip_forward", "iptables -t nat -A", "iptables -t filter -A", `family="ipv4"`, "--add-masquerade"} {
			if strings.Contains(all, unexpected) {
				t.Errorf("IPv6-only setup must not change IPv4 behavior: %s", unexpected)
			}
		}
	})
	t.Run("creates macvlan with host sibling gateway and NAT", func(t *testing.T) {
		r := &egNetRunner{}
		// Use /120 IPv6 like metal dualstack MachineNetworks.
		if err := ensureExternalGatewayNetwork(r, hostNet, "192.168.111.0/24", "fd2e:6f44:5dd8:c956::/120"); err != nil {
			t.Fatalf("ensureExternalGatewayNetwork() error = %v", err)
		}
		all := strings.Join(r.cmds, "\n")
		for _, want := range []string{
			"ip link add " + bmExGwHostLinkName + " link baremetal type macvlan mode bridge",
			"ip addr add 192.168.111.239/32 dev " + bmExGwHostLinkName,
			"ip addr add fd2e:6f44:5dd8:c956::ef/128 dev " + bmExGwHostLinkName + " nodad",
			"ip route replace 192.168.111.240/28 dev " + bmExGwHostLinkName,
			"ip -6 route replace fd2e:6f44:5dd8:c956::f0/124 dev " + bmExGwHostLinkName,
			"sysctl -w net.ipv4.ip_forward=1",
			"sysctl -w net.ipv6.conf.all.forwarding=1",
			"firewall-cmd --zone=public --change-interface=" + bmExGwHostLinkName,
			"iptables -t nat -A OVN-EXGW-NAT -s 192.168.111.240/28 -j MASQUERADE",
			"ip6tables -t nat -A OVN-EXGW-NAT -s fd2e:6f44:5dd8:c956::f0/124 -j MASQUERADE",
		} {
			if !strings.Contains(all, want) {
				t.Errorf("commands missing %q\n%s", want, all)
			}
		}
		wantArgs := []string{"network", "create", "-d", "macvlan", "-o", "parent=baremetal",
			"--subnet", "192.168.111.0/24", "--ip-range", "192.168.111.240/28", "--gateway", "192.168.111.239",
			"--subnet", "fd2e:6f44:5dd8:c956::/120", "--ip-range", "fd2e:6f44:5dd8:c956::f0/124", "--gateway", "fd2e:6f44:5dd8:c956::ef", "--ipv6", bmExGwNetworkName}
		if !reflect.DeepEqual(r.createArgs, wantArgs) {
			t.Errorf("network create arguments = %q, want %q", r.createArgs, wantArgs)
		}
		if strings.Contains(all, "--zone=trusted --add-interface="+bmExGwHostLinkName) {
			t.Fatal("must not trust all host input on gateway sibling")
		}
		for _, cidr := range []string{"192.168.111.240/28", "fd2e:6f44:5dd8:c956::f0/124"} {
			if !strings.Contains(all, `source address="`+cidr+`" accept`) {
				t.Errorf("missing source-scoped forwarding rule for %s", cidr)
			}
		}
		if strings.Contains(all, "firewall-cmd --reload") || strings.Contains(all, "--add-masquerade") || strings.Contains(all, "firewall-cmd --permanent") {
			t.Fatal("lazy gateway setup must not reload or change zone-wide/permanent firewall settings")
		}
		for _, family := range []struct{ name, pool string }{{"ipv4", "192.168.111.240/28"}, {"ipv6", "fd2e:6f44:5dd8:c956::f0/124"}} {
			rule := fmt.Sprintf(`rule family=%q source address=%q masquerade`, family.name, family.pool)
			if !strings.Contains(all, rule) {
				t.Errorf("missing pool-scoped NAT rule %s", rule)
			}
		}
		if !strings.Contains(all, "--add-egress-zone=ANY") {
			t.Fatal("forwarding policy must exclude host input")
		}

		if strings.Contains(r.createCmd, "--gateway 192.168.111.1") {
			t.Errorf("must not use parent host IP as gateway: %q", r.createCmd)
		}
		if strings.Contains(r.createCmd, "--internal") {
			t.Errorf("create command must not use --internal: %q", r.createCmd)
		}
	})

	t.Run("replaces leftover wide-prefix gateway addresses on reuse", func(t *testing.T) {
		r := &egNetRunner{
			linkExists: true,
			addrs: []egMockAddr{
				{Family: "inet", Local: "192.168.111.239", PrefixLen: 24},
				{Family: "inet6", Local: "fd2e:6f44:5dd8:c956::ef", PrefixLen: 120},
			},
		}
		if err := ensureExternalGatewayNetwork(r, hostNet, "192.168.111.0/24", "fd2e:6f44:5dd8:c956::/120"); err != nil {
			t.Fatalf("ensureExternalGatewayNetwork() error = %v", err)
		}
		all := strings.Join(r.cmds, "\n")
		for _, want := range []string{
			"ip addr del 192.168.111.239/24 dev " + bmExGwHostLinkName,
			"ip addr del fd2e:6f44:5dd8:c956::ef/120 dev " + bmExGwHostLinkName,
			"ip addr add 192.168.111.239/32 dev " + bmExGwHostLinkName,
			"ip addr add fd2e:6f44:5dd8:c956::ef/128 dev " + bmExGwHostLinkName + " nodad",
		} {
			if !strings.Contains(all, want) {
				t.Errorf("commands missing %q\n%s", want, all)
			}
		}
		for _, pair := range [][2]string{
			{"ip addr del 192.168.111.239/24 dev " + bmExGwHostLinkName, "ip addr add 192.168.111.239/32 dev " + bmExGwHostLinkName},
			{"ip addr del fd2e:6f44:5dd8:c956::ef/120 dev " + bmExGwHostLinkName, "ip addr add fd2e:6f44:5dd8:c956::ef/128 dev " + bmExGwHostLinkName + " nodad"},
		} {
			if strings.Index(all, pair[0]) >= strings.Index(all, pair[1]) {
				t.Errorf("address migration must delete %q before adding %q", pair[0], pair[1])
			}
		}
		if strings.Contains(all, "ip link add "+bmExGwHostLinkName) {
			t.Errorf("must not recreate existing %s link", bmExGwHostLinkName)
		}
	})

	t.Run("requires parent interface", func(t *testing.T) {
		r := &egNetRunner{}
		err := ensureExternalGatewayNetwork(r, &api.NetworkInterface{}, "192.168.111.0/24", "")
		if err == nil {
			t.Fatal("expected error for missing parent interface")
		}
	})
}
