package infraprovider

import (
	"testing"
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
		name     string
		json     string
		v4Subnet string
		v6Subnet string
		want     string
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
			name:     "malformed JSON",
			json:     `{invalid`,
			v4Subnet: "192.168.111.0/24",
			want:     "",
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
			got := findInterfaceBySubnet(tt.json, tt.v4Subnet, tt.v6Subnet)
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
