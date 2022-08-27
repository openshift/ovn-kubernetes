//go:build linux
// +build linux

package cni

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"k8s.io/client-go/kubernetes"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/safchain/ethtool"
	"github.com/vishvananda/netlink"
)

type CNIPluginLibOps interface {
	AddRoute(ipn *net.IPNet, gw net.IP, dev netlink.Link, mtu int) error
	SetupVeth(contVethName string, hostVethName string, mtu int, hostNS ns.NetNS) (net.Interface, net.Interface, error)
}

type defaultCNIPluginLibOps struct{}

var cniPluginLibOps CNIPluginLibOps = &defaultCNIPluginLibOps{}

func (defaultCNIPluginLibOps) AddRoute(ipn *net.IPNet, gw net.IP, dev netlink.Link, mtu int) error {
	route := &netlink.Route{
		LinkIndex: dev.Attrs().Index,
		Scope:     netlink.SCOPE_UNIVERSE,
		Dst:       ipn,
		Gw:        gw,
		MTU:       mtu,
	}

	return util.GetNetLinkOps().RouteAdd(route)
}

func (defaultCNIPluginLibOps) SetupVeth(contVethName string, hostVethName string, mtu int, hostNS ns.NetNS) (net.Interface, net.Interface, error) {
	return ip.SetupVethWithName(contVethName, hostVethName, mtu, hostNS)
}

// This is a good value that allows fast streams of small packets to be aggregated,
// without introducing noticeable latency in slower traffic.
const udpPacketAggregationTimeout = 50 * time.Microsecond

var udpPacketAggregationTimeoutBytes = []byte(fmt.Sprintf("%d\n", udpPacketAggregationTimeout.Nanoseconds()))

// sets up the host side of a veth for UDP packet aggregation
func setupVethUDPAggregationHost(ifname string) error {
	e, err := ethtool.NewEthtool()
	if err != nil {
		return fmt.Errorf("failed to initialize ethtool: %v", err)
	}
	defer e.Close()

	err = e.Change(ifname, map[string]bool{
		"rx-gro":                true,
		"rx-udp-gro-forwarding": true,
	})
	if err != nil {
		return fmt.Errorf("could not enable interface features: %v", err)
	}
	channels, err := e.GetChannels(ifname)
	if err == nil {
		channels.RxCount = uint32(runtime.NumCPU())
		_, err = e.SetChannels(ifname, channels)
	}
	if err != nil {
		return fmt.Errorf("could not update channels: %v", err)
	}

	timeoutFile := fmt.Sprintf("/sys/class/net/%s/gro_flush_timeout", ifname)
	err = os.WriteFile(timeoutFile, udpPacketAggregationTimeoutBytes, 0644)
	if err != nil {
		return fmt.Errorf("could not set flush timeout: %v", err)
	}

	return nil
}

// sets up the container side of a veth for UDP packet aggregation
func setupVethUDPAggregationContainer(ifname string) error {
	e, err := ethtool.NewEthtool()
	if err != nil {
		return fmt.Errorf("failed to initialize ethtool: %v", err)
	}
	defer e.Close()

	channels, err := e.GetChannels(ifname)
	if err == nil {
		channels.TxCount = uint32(runtime.NumCPU())
		_, err = e.SetChannels(ifname, channels)
	}
	if err != nil {
		return fmt.Errorf("could not update channels: %v", err)
	}

	return nil
}

func renameLink(curName, newName string) error {
	link, err := util.GetNetLinkOps().LinkByName(curName)
	if err != nil {
		return err
	}

	if err := util.GetNetLinkOps().LinkSetDown(link); err != nil {
		return err
	}
	if err := util.GetNetLinkOps().LinkSetName(link, newName); err != nil {
		return err
	}
	if err := util.GetNetLinkOps().LinkSetUp(link); err != nil {
		return err
	}

	return nil
}

func setSysctl(sysctl string, newVal int) error {
	return ioutil.WriteFile(sysctl, []byte(strconv.Itoa(newVal)), 0o640)
}

func moveIfToNetns(ifname string, netns ns.NetNS) error {
	vfDev, err := util.GetNetLinkOps().LinkByName(ifname)
	if err != nil {
		return fmt.Errorf("failed to lookup vf device %v: %q", ifname, err)
	}

	// move VF device to ns
	if err = util.GetNetLinkOps().LinkSetNsFd(vfDev, int(netns.Fd())); err != nil {
		return fmt.Errorf("failed to move device %+v to netns: %q", ifname, err)
	}

	return nil
}

func setupNetwork(link netlink.Link, ifInfo *PodInterfaceInfo, logf *os.File) error {
	start := time.Now()
	// set the mac addresss, set down the interface before changing the mac
	// so the EUI64 link local address generated uses the new MAC when we set it up again
	if err := util.GetNetLinkOps().LinkSetDown(link); err != nil {
		return fmt.Errorf("failed to set down interface %s: %v", link.Attrs().Name, err)
	}
	logf.WriteString(fmt.Sprintf("         NetSetDown: %v\n", time.Since(start)))
	start = time.Now()
	if err := util.GetNetLinkOps().LinkSetHardwareAddr(link, ifInfo.MAC); err != nil {
		return fmt.Errorf("failed to add mac address %s to %s: %v", ifInfo.MAC, link.Attrs().Name, err)
	}
	logf.WriteString(fmt.Sprintf("         NetSetHWAddr: %v\n", time.Since(start)))
	start = time.Now()
	if err := util.GetNetLinkOps().LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to set up interface %s: %v", link.Attrs().Name, err)
	}
	logf.WriteString(fmt.Sprintf("         NetSetUp: %v\n", time.Since(start)))
	start = time.Now()

	// set the IP address
	for _, ip := range ifInfo.IPs {
		addr := &netlink.Addr{IPNet: ip}
		if err := util.GetNetLinkOps().AddrAdd(link, addr); err != nil {
			return fmt.Errorf("failed to add IP addr %s to %s: %v", ip, link.Attrs().Name, err)
		}
	}
	logf.WriteString(fmt.Sprintf("         NetSetIPs: %v\n", time.Since(start)))
	start = time.Now()
	for _, gw := range ifInfo.Gateways {
		if err := cniPluginLibOps.AddRoute(nil, gw, link, ifInfo.RoutableMTU); err != nil {
			return fmt.Errorf("failed to add gateway route: %v", err)
		}
	}
	logf.WriteString(fmt.Sprintf("         NetSetGWs: %v\n", time.Since(start)))
	start = time.Now()
	for _, route := range ifInfo.Routes {
		if err := cniPluginLibOps.AddRoute(route.Dest, route.NextHop, link, ifInfo.RoutableMTU); err != nil {
			return fmt.Errorf("failed to add pod route %v via %v: %v", route.Dest, route.NextHop, err)
		}
	}
	logf.WriteString(fmt.Sprintf("         NetSetRoutes: %v\n", time.Since(start)))
	start = time.Now()

	return nil
}

func setupInterface(netns ns.NetNS, containerID, ifName string, ifInfo *PodInterfaceInfo, logf *os.File) (*current.Interface, *current.Interface, error) {
	hostIface := &current.Interface{}
	contIface := &current.Interface{}

	start := time.Now()
	err := netns.Do(func(hostNS ns.NetNS) error {
		logf.WriteString(fmt.Sprintf("      SetupNSDo: %v\n", time.Since(start)))

		// create the veth pair in the container and move host end into host netns
		hostIface.Name = containerID[:15]
		start = time.Now()
		hostVeth, containerVeth, err := cniPluginLibOps.SetupVeth(ifName, hostIface.Name, ifInfo.MTU, hostNS)
		logf.WriteString(fmt.Sprintf("      SetupVeth: %v\n", time.Since(start)))
		if err != nil {
			return err
		}
		hostIface.Mac = hostVeth.HardwareAddr.String()
		contIface.Name = containerVeth.Name

		start = time.Now()
		link, err := util.GetNetLinkOps().LinkByName(contIface.Name)
		logf.WriteString(fmt.Sprintf("      LinkByName: %v\n", time.Since(start)))
		if err != nil {
			return fmt.Errorf("failed to lookup %s: %v", contIface.Name, err)
		}

		start = time.Now()
		err = setupNetwork(link, ifInfo, logf)
		logf.WriteString(fmt.Sprintf("      SetupNet: %v\n", time.Since(start)))
		if err != nil {
			return err
		}
		contIface.Mac = ifInfo.MAC.String()
		contIface.Sandbox = netns.Path()

		if ifInfo.EnableUDPAggregation {
			err = setupVethUDPAggregationContainer(contIface.Name)
			if err != nil {
				return fmt.Errorf("could not enable UDP packet aggregation in container: %v", err)
			}
		}

		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	if ifInfo.EnableUDPAggregation {
		err = setupVethUDPAggregationHost(hostIface.Name)
		if err != nil {
			return nil, nil, fmt.Errorf("could not enable UDP packet aggregation on host veth interface %q: %v", hostIface.Name, err)
		}
	}

	return hostIface, contIface, nil
}

// Setup sriov interface in the pod
func setupSriovInterface(netns ns.NetNS, containerID, ifName string, ifInfo *PodInterfaceInfo, pciAddrs string, logf *os.File) (*current.Interface, *current.Interface, error) {
	hostIface := &current.Interface{}
	contIface := &current.Interface{}

	// 1. get the VF's netdevName that was stashed early on
	vfNetdevice := ifInfo.VfNetdevName

	if !ifInfo.IsDPUHostMode {
		// 2. get Uplink netdevice
		uplink, err := util.GetSriovnetOps().GetUplinkRepresentor(pciAddrs)
		if err != nil {
			return nil, nil, err
		}

		// 3. get VF index from PCI
		vfIndex, err := util.GetSriovnetOps().GetVfIndexByPciAddress(pciAddrs)
		if err != nil {
			return nil, nil, err
		}

		// 4. lookup representor
		rep, err := util.GetSriovnetOps().GetVfRepresentor(uplink, vfIndex)
		if err != nil {
			return nil, nil, err
		}
		oldHostRepName := rep

		// 5. rename the host VF representor
		hostIface.Name = containerID[:15]
		if err = renameLink(oldHostRepName, hostIface.Name); err != nil {
			return nil, nil, fmt.Errorf("failed to rename %s to %s: %v", oldHostRepName, hostIface.Name, err)
		}
		link, err := util.GetNetLinkOps().LinkByName(hostIface.Name)
		if err != nil {
			return nil, nil, err
		}
		hostIface.Mac = link.Attrs().HardwareAddr.String()

		// 6. set MTU on VF representor
		if err = util.GetNetLinkOps().LinkSetMTU(link, ifInfo.MTU); err != nil {
			return nil, nil, fmt.Errorf("failed to set MTU on %s: %v", hostIface.Name, err)
		}
	}

	// 7. Move VF to Container namespace
	err := moveIfToNetns(vfNetdevice, netns)
	if err != nil {
		return nil, nil, err
	}

	err = netns.Do(func(hostNS ns.NetNS) error {
		contIface.Name = ifName
		err = renameLink(vfNetdevice, contIface.Name)
		if err != nil {
			return err
		}
		link, err := util.GetNetLinkOps().LinkByName(contIface.Name)
		if err != nil {
			return err
		}
		err = util.GetNetLinkOps().LinkSetMTU(link, ifInfo.MTU)
		if err != nil {
			return err
		}
		err = util.GetNetLinkOps().LinkSetUp(link)
		if err != nil {
			return err
		}

		err = setupNetwork(link, ifInfo, logf)
		if err != nil {
			return err
		}

		contIface.Mac = ifInfo.MAC.String()
		contIface.Sandbox = netns.Path()

		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	return hostIface, contIface, nil
}

// ConfigureOVS performs OVS configurations in order to set up Pod networking
func ConfigureOVS(ctx context.Context, namespace, podName, hostIfaceName string,
	ifInfo *PodInterfaceInfo, sandboxID string, podLister corev1listers.PodLister,
	kclient kubernetes.Interface, logf *os.File) error {
	klog.Infof("ConfigureOVS: namespace: %s, podName: %s", namespace, podName)
	ifaceID := util.GetIfaceId(namespace, podName)
	initialPodUID := ifInfo.PodUID

	// Find and remove any existing OVS port with this iface-id. Pods can
	// have multiple sandboxes if some are waiting for garbage collection,
	// but only the latest one should have the iface-id set.
	start := time.Now()
	uuids, _ := ovsFind("Interface", "_uuid", "external-ids:iface-id="+ifaceID)
	logf.WriteString(fmt.Sprintf("      ConfOVSFind: %v\n", time.Since(start)))
	start = time.Now()
	for _, uuid := range uuids {
		if out, err := ovsExec("remove", "Interface", uuid, "external-ids", "iface-id"); err != nil {
			klog.Warningf("Failed to clear stale OVS port %q iface-id %q: %v\n  %q", uuid, ifaceID, err, out)
		}
	}
	logf.WriteString(fmt.Sprintf("      ConfOVSRemove: %v\n", time.Since(start)))
	start = time.Now()
	ipStrs := make([]string, len(ifInfo.IPs))
	for i, ip := range ifInfo.IPs {
		ipStrs[i] = ip.String()
	}
	// Add the new sandbox's OVS port, tag the port as transient so stale
	// pod ports are scrubbed on hard reboot
	ovsArgs := []string{
		"add-port", "br-int", hostIfaceName, "other_config:transient=true", "--", "set",
		"interface", hostIfaceName,
		fmt.Sprintf("external_ids:attached_mac=%s", ifInfo.MAC),
		fmt.Sprintf("external_ids:iface-id=%s", ifaceID),
		fmt.Sprintf("external_ids:iface-id-ver=%s", initialPodUID),
		fmt.Sprintf("external_ids:ip_addresses=%s", strings.Join(ipStrs, ",")),
		fmt.Sprintf("external_ids:sandbox=%s", sandboxID),
	}

	if len(ifInfo.VfNetdevName) != 0 {
		ovsArgs = append(ovsArgs, fmt.Sprintf("external_ids:vf-netdev-name=%s", ifInfo.VfNetdevName))
	}
	if out, err := ovsExec(ovsArgs...); err != nil {
		return fmt.Errorf("failure in plugging pod interface: %v\n  %q", err, out)
	}
	logf.WriteString(fmt.Sprintf("      ConfOVSAddPort: %v\n", time.Since(start)))
	start = time.Now()

	if err := clearPodBandwidth(sandboxID); err != nil {
		return err
	}
	logf.WriteString(fmt.Sprintf("      ConfOVSClearBW: %v\n", time.Since(start)))
	start = time.Now()

	if ifInfo.Ingress > 0 || ifInfo.Egress > 0 {
		l, err := netlink.LinkByName(hostIfaceName)
		if err != nil {
			return fmt.Errorf("failed to find host veth interface %s: %v", hostIfaceName, err)
		}
		err = netlink.LinkSetTxQLen(l, 1000)
		if err != nil {
			return fmt.Errorf("failed to set host veth txqlen: %v", err)
		}

		if err := setPodBandwidth(sandboxID, hostIfaceName, ifInfo.Ingress, ifInfo.Egress); err != nil {
			return err
		}
	}

	start = time.Now()
	if err := waitForPodInterface(ctx, ifInfo.MAC.String(), ifInfo.IPs, hostIfaceName,
		ifaceID, ifInfo.CheckExtIDs, podLister, kclient, namespace, podName,
		initialPodUID, logf); err != nil {
		// Ensure the error shows up in node logs, rather than just
		// being reported back to the runtime.
		klog.Warningf("[%s/%s %s] pod uid %s: %v", namespace, podName, sandboxID, initialPodUID, err)
		return err
	}
	logf.WriteString(fmt.Sprintf("      ConfOVSWait(%v): %v\n", ifInfo.CheckExtIDs, time.Since(start)))
	return nil
}

// ConfigureInterface sets up the container interface
func (pr *PodRequest) ConfigureInterface(podLister corev1listers.PodLister, kclient kubernetes.Interface, ifInfo *PodInterfaceInfo) ([]*current.Interface, error) {
	start := time.Now()
	netns, err := ns.GetNS(pr.Netns)
	pr.logf.WriteString(fmt.Sprintf("   GetNS: %v\n", time.Since(start)))
	if err != nil {
		return nil, fmt.Errorf("failed to open netns %q: %v", pr.Netns, err)
	}
	defer netns.Close()

	var hostIface, contIface *current.Interface

	klog.V(5).Infof("CNI Conf %v", pr.CNIConf)
	if pr.CNIConf.DeviceID != "" {
		// SR-IOV Case
		hostIface, contIface, err = setupSriovInterface(netns, pr.SandboxID, pr.IfName, ifInfo, pr.CNIConf.DeviceID, pr.logf)
	} else {
		if ifInfo.IsDPUHostMode {
			return nil, fmt.Errorf("unexpected configuration, pod request on dpu host. " +
				"device ID must be provided")
		}
		// General case
		start = time.Now()
		hostIface, contIface, err = setupInterface(netns, pr.SandboxID, pr.IfName, ifInfo, pr.logf)
		pr.logf.WriteString(fmt.Sprintf("   Setup: %v\n", time.Since(start)))
	}
	if err != nil {
		return nil, err
	}

	if !ifInfo.IsDPUHostMode {
		start = time.Now()
		err = ConfigureOVS(pr.ctx, pr.PodNamespace, pr.PodName, hostIface.Name, ifInfo, pr.SandboxID,
			podLister, kclient, pr.logf)
		pr.logf.WriteString(fmt.Sprintf("   ConfOVS: %v\n", time.Since(start)))
		if err != nil {
			pr.deletePorts(hostIface.Name, pr.PodNamespace, pr.PodName)
			return nil, err
		}
	}

	// OCP HACK: block access to MCS/metadata; https://github.com/openshift/ovn-kubernetes/pull/19
	start = time.Now()
	err = setupIPTablesBlocks(netns, ifInfo)
	pr.logf.WriteString(fmt.Sprintf("   IPTables: %v\n", time.Since(start)))
	if err != nil {
		return nil, err
	}
	// END OCP HACK

	return []*current.Interface{hostIface, contIface}, nil
}

func (pr *PodRequest) UnconfigureInterface(ifInfo *PodInterfaceInfo) error {
	podDesc := fmt.Sprintf("for pod %s/%s", pr.PodNamespace, pr.PodName)
	klog.V(5).Infof("Tear down interface (%+v) %s", *pr, podDesc)
	if pr.CNIConf.DeviceID == "" {
		if ifInfo.IsDPUHostMode {
			klog.Warningf("Unexpected configuration %s, Device ID must be present for pod request on smart-nic host",
				podDesc)
			return nil
		}
	} else {
		// For SRIOV case, we'd need to move the VF from container namespace back to the host namespace
		netns, err := ns.GetNS(pr.Netns)
		if err != nil {
			return fmt.Errorf("failed to get container namespace %s: %v", podDesc, err)
		}
		defer netns.Close()

		hostNS, err := ns.GetCurrentNS()
		if err != nil {
			return fmt.Errorf("failed to get host namespace %s: %v", podDesc, err)
		}
		defer hostNS.Close()

		err = netns.Do(func(_ ns.NetNS) error {
			// container side interface deletion
			link, err := util.GetNetLinkOps().LinkByName(pr.IfName)
			if err != nil {
				return fmt.Errorf("failed to get container interface %s %s: %v", pr.IfName, podDesc, err)
			}
			err = util.GetNetLinkOps().LinkSetDown(link)
			if err != nil {
				return fmt.Errorf("failed to bring down container interface %s %s: %v", pr.IfName, podDesc, err)
			}
			// rename VF device back to its original name in the host namespace:
			err = util.GetNetLinkOps().LinkSetName(link, ifInfo.VfNetdevName)
			if err != nil {
				return fmt.Errorf("failed to rename container interface %s to %s %s: %v",
					pr.IfName, ifInfo.VfNetdevName, podDesc, err)
			}
			// move VF device to host netns
			err = util.GetNetLinkOps().LinkSetNsFd(link, int(hostNS.Fd()))
			if err != nil {
				return fmt.Errorf("failed to move container interface %s back to host namespace %s: %v",
					pr.IfName, podDesc, err)
			}
			return nil
		})
		if err != nil {
			klog.Errorf(err.Error())
		}
	}

	if ifInfo.IsDPUHostMode {
		// there is nothing else to do in the DPU-Host mode
		return nil
	}

	// host side deletion of OVS port and kernel interface
	ifName := pr.SandboxID[:15]
	pr.deletePorts(ifName, pr.PodNamespace, pr.PodName)

	if err := clearPodBandwidth(pr.SandboxID); err != nil {
		klog.Warningf("Failed to clearPodBandwidth sandbox %v %s: %v", pr.SandboxID, podDesc, err)
	}
	pr.deletePodConntrack()
	return nil
}

func (pr *PodRequest) deletePodConntrack() {
	if pr.CNIConf.PrevResult == nil {
		return
	}
	result, err := current.NewResultFromResult(pr.CNIConf.PrevResult)
	if err != nil {
		klog.Warningf("Could not convert result to current version: %v", err)
		return
	}

	for _, ip := range result.IPs {
		// Skip known non-sandbox interfaces
		if ip.Interface != nil {
			intIdx := *ip.Interface
			if intIdx >= 0 &&
				intIdx < len(result.Interfaces) && result.Interfaces[intIdx].Sandbox == "" {
				continue
			}
		}
		err = util.DeleteConntrack(ip.Address.IP.String(), 0, "", netlink.ConntrackReplyAnyIP, nil)
		if err != nil {
			klog.Errorf("Failed to delete Conntrack Entry for %s: %v", ip.Address.IP.String(), err)
			continue
		}
	}
}

func (pr *PodRequest) deletePorts(ifaceName, podNamespace, podName string) {
	podDesc := fmt.Sprintf("%s/%s", podNamespace, podName)

	out, err := ovsExec("del-port", "br-int", ifaceName)
	if err != nil && !strings.Contains(err.Error(), "no port named") {
		// DEL should be idempotent; don't return an error just log it
		klog.Warningf("Failed to delete pod %q OVS port %s: %v\n  %q", podDesc, ifaceName, err, string(out))
	}
	// skip deleting representor ports
	if pr.CNIConf.DeviceID == "" {
		if err = util.LinkDelete(ifaceName); err != nil {
			klog.Warningf("Failed to delete pod %q interface %s: %v", podDesc, ifaceName, err)
		}
	}
}
