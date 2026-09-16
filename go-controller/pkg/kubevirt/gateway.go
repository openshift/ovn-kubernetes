// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package kubevirt

import (
	"fmt"
	"net"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

type ipv4Gateway struct {
	ip  net.IP
	mac net.HardwareAddr
}

func sendGatewayGARPs(interfaceName string, gateways []ipv4Gateway, destinationMAC net.HardwareAddr, unicastGARP func(string, util.GARP, net.HardwareAddr) error) error {
	for _, gateway := range gateways {
		garp, err := util.NewGARP(gateway.ip, &gateway.mac)
		if err != nil {
			return fmt.Errorf("failed to create GARP for gateway IP %s: %w", gateway.ip, err)
		}
		if err := unicastGARP(interfaceName, garp, destinationMAC); err != nil {
			return fmt.Errorf("failed sending GARP for gateway %s: %w", gateway.ip, err)
		}
	}
	return nil
}
