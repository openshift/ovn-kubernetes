package infraprovider

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFindNetworkInterfaceForSubnets(t *testing.T) {
	links := []linkInfo{
		{
			IfName: "lo",
			Mac:    "00:00:00:00:00:00",
			AddrInfo: []ipAddressInfo{
				{Family: "inet", Local: "127.0.0.1", PrefixLen: 8},
				{Family: "inet6", Local: "::1", PrefixLen: 128},
			},
		},
		{
			IfName: "enp0s3",
			Mac:    "02:00:00:00:00:01",
			AddrInfo: []ipAddressInfo{
				{Family: "inet", Local: "192.168.111.22", PrefixLen: 24},
				{Family: "inet6", Local: "fd2e:6f44:5dd8:c956::22", PrefixLen: 64},
			},
		},
	}

	t.Run("dual stack", func(t *testing.T) {
		got, err := findNetworkInterfaceForSubnets(links, "192.168.111.0/24", "fd2e:6f44:5dd8:c956::/64")
		require.NoError(t, err)
		require.Equal(t, "enp0s3", got.InfName)
		require.Equal(t, "02:00:00:00:00:01", got.MAC)
		require.Equal(t, "192.168.111.22", got.IPv4)
		require.Equal(t, "24", got.IPv4Prefix)
		require.Equal(t, "fd2e:6f44:5dd8:c956::22", got.IPv6)
		require.Equal(t, "64", got.IPv6Prefix)
	})

	t.Run("IPv6 only", func(t *testing.T) {
		got, err := findNetworkInterfaceForSubnets(links, "", "fd2e:6f44:5dd8:c956::/64")
		require.NoError(t, err)
		require.Empty(t, got.IPv4)
		require.Equal(t, "fd2e:6f44:5dd8:c956::22", got.IPv6)
	})

	t.Run("no match", func(t *testing.T) {
		_, err := findNetworkInterfaceForSubnets(links, "10.0.0.0/24", "")
		require.ErrorContains(t, err, "no node network interface found")
	})
}
