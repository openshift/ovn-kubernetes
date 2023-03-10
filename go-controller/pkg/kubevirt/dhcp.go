package kubevirt

import (
	"fmt"
	"net"

	utilnet "k8s.io/utils/net"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdbops"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

const (
	dhcpLeaseTime = 3500
)

func ComposeDHCPConfigs(k8scli *factory.WatchFactory, controllerName, namespace, vmName string, ips []*net.IPNet) (*libovsdbops.DHCPConfigs, error) {
	if len(ips) == 0 {
		return nil, fmt.Errorf("missing ips to compose dhcp options")
	}
	if vmName == "" {
		return nil, fmt.Errorf("missing vmName to compose dhcp options")
	}

	dnsServerIPv4, dnsServerIPv6, err := retrieveDNSServiceClusterIPs(k8scli)
	if err != nil {
		return nil, fmt.Errorf("failed retrieving dns service cluster ip: %v", err)
	}

	dhcpConfigs := &libovsdbops.DHCPConfigs{}
	for _, ip := range ips {
		_, cidr, err := net.ParseCIDR(ip.String())
		if err != nil {
			return nil, fmt.Errorf("failed converting ips to cidr to configure dhcp: %v", err)
		}
		if utilnet.IsIPv4CIDR(cidr) {
			dhcpConfigs.V4 = ComposeDHCPv4Config(cidr.String(), dnsServerIPv4, controllerName, namespace, vmName)
		} else if utilnet.IsIPv6CIDR(cidr) {
			dhcpConfigs.V6 = ComposeDHCPv6Config(cidr.String(), dnsServerIPv6, controllerName, namespace, vmName)
		}
	}
	return dhcpConfigs, nil
}

func retrieveDNSServiceClusterIPs(k8scli *factory.WatchFactory) (string, string, error) {
	dnsServer, err := k8scli.GetService(config.Kubernetes.DNSServiceNamespace, config.Kubernetes.DNSServiceName)
	if err != nil {
		return "", "", err
	}
	clusterIPv4 := ""
	clusterIPv6 := ""
	for _, clusterIP := range dnsServer.Spec.ClusterIPs {
		if utilnet.IsIPv4String(clusterIP) {
			clusterIPv4 = clusterIP
		} else if utilnet.IsIPv6String(clusterIP) {
			clusterIPv6 = clusterIP
		}
	}
	return clusterIPv4, clusterIPv6, nil
}

func ComposeDHCPv4Config(cidr, dnsServer, controllerName, namespace, vmName string) *libovsdbops.DHCPConfig {
	serverMAC := util.IPAddrToHWAddr(net.ParseIP(ARPProxyIPv4)).String()
	dhcpOptions := &nbdb.DHCPOptions{
		Cidr: cidr,
		Options: map[string]string{
			"lease_time": fmt.Sprintf("%d", dhcpLeaseTime),
			"router":     ARPProxyIPv4,
			"dns_server": dnsServer,
			"server_id":  ARPProxyIPv4,
			"server_mac": serverMAC,
			"hostname":   fmt.Sprintf("%q", vmName),
		},
	}
	return composeDHCPConfig(controllerName, namespace, vmName, dhcpOptions)
}

func ComposeDHCPv6Config(cidr, dnsServer, controllerName, namespace, vmName string) *libovsdbops.DHCPConfig {
	serverMAC := util.IPAddrToHWAddr(net.ParseIP(ARPProxyIPv6)).String()
	dhcpOptions := &nbdb.DHCPOptions{
		Cidr: cidr,
		Options: map[string]string{
			"server_id": serverMAC,
		},
	}
	if dnsServer != "" {
		dhcpOptions.Options["dns_server"] = dnsServer
	}
	return composeDHCPConfig(controllerName, namespace, vmName, dhcpOptions)
}

func composeDHCPConfig(controllerName, namespace, vmName string, dhcpOptions *nbdb.DHCPOptions) *libovsdbops.DHCPConfig {
	dhcpvOptionsDbObjectID := libovsdbops.NewDbObjectIDs(libovsdbops.VirtualMachineDHCPOptions, controllerName,
		map[libovsdbops.ExternalIDKey]string{
			libovsdbops.ObjectNameKey:       dhcpOptions.Cidr,
			libovsdbops.VirtualMachineIndex: vmName,
			libovsdbops.NamespaceIndex:      namespace,
		})
	dhcpOptions.ExternalIDs = dhcpvOptionsDbObjectID.GetExternalIDs()
	dhcpOptions.ExternalIDs[OvnZoneExternalIDKey] = OvnLocalZone
	return &libovsdbops.DHCPConfig{
		Options: dhcpOptions,
	}
}
