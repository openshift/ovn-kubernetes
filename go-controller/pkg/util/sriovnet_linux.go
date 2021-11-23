// +build linux

package util

import (
	"net"

	"github.com/Mellanox/sriovnet"
)

type SriovnetOps interface {
	GetNetDevicesFromPci(pciAddress string) ([]string, error)
	GetUplinkRepresentor(vfPciAddress string) (string, error)
	GetVfIndexByPciAddress(vfPciAddress string) (int, error)
	GetVfRepresentor(uplink string, vfIndex int) (string, error)
	GetPfPciFromVfPci(vfPciAddress string) (string, error)
	GetVfRepresentorDPU(pfID, vfIndex string) (string, error)
	GetRepresentorPeerMacAddress(netdev string) (net.HardwareAddr, error)
	GetRepresentorPortFlavour(netdev string) (sriovnet.PortFlavour, error)
}

type defaultSriovnetOps struct {
}

var sriovnetOps SriovnetOps = &defaultSriovnetOps{}

// SetSriovnetOpsInst method would be used by unit tests in other packages
func SetSriovnetOpsInst(mockInst SriovnetOps) {
	sriovnetOps = mockInst
}

// GetSriovnetOps will be invoked by functions in other packages that would need access to the sriovnet library methods.
func GetSriovnetOps() SriovnetOps {
	return sriovnetOps
}

func (defaultSriovnetOps) GetNetDevicesFromPci(pciAddress string) ([]string, error) {
	return sriovnet.GetNetDevicesFromPci(pciAddress)
}

func (defaultSriovnetOps) GetUplinkRepresentor(vfPciAddress string) (string, error) {
	return sriovnet.GetUplinkRepresentor(vfPciAddress)
}

func (defaultSriovnetOps) GetVfIndexByPciAddress(vfPciAddress string) (int, error) {
	return sriovnet.GetVfIndexByPciAddress(vfPciAddress)
}

func (defaultSriovnetOps) GetVfRepresentor(uplink string, vfIndex int) (string, error) {
	return sriovnet.GetVfRepresentor(uplink, vfIndex)
}

func (defaultSriovnetOps) GetPfPciFromVfPci(vfPciAddress string) (string, error) {
	return sriovnet.GetPfPciFromVfPci(vfPciAddress)
}

func (defaultSriovnetOps) GetVfRepresentorDPU(pfID, vfIndex string) (string, error) {
	return sriovnet.GetVfRepresentorDPU(pfID, vfIndex)
}

func (defaultSriovnetOps) GetRepresentorPeerMacAddress(netdev string) (net.HardwareAddr, error) {
	return sriovnet.GetRepresentorPeerMacAddress(netdev)
}

func (defaultSriovnetOps) GetRepresentorPortFlavour(netdev string) (sriovnet.PortFlavour, error) {
	return sriovnet.GetRepresentorPortFlavour(netdev)
}
