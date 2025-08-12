package feature

import (
	"github.com/onsi/ginkgo/v2"
	"github.com/ovn-org/ovn-kubernetes/test/e2e/label"
)

var (
	Service               = New("Service")
	NetworkPolicy         = New("NetworkPolicy")
	AdminNetworkPolicy    = New("AdminNetworkPolicy")
	BaselineNetworkPolicy = New("BaselineNetworkPolicy")
	NetworkSegmentation   = New("NetworkSegmentation")
	EgressIP              = New("EgressIP")
	EgressService         = New("EgressService")
	EgressFirewall        = New("EgressFirewall")
	EgressQos             = New("EgressQos")
	ExternalGateway       = New("ExternalGateway")
	DisablePacketMTUCheck = New("DisablePacketMTUCheck")
	VirtualMachineSupport = New("VirtualMachineSupport")
	Interconnect          = New("Interconnect")
	Multicast             = New("Multicast")
	MultiHoming           = New("MultiHoming")
	NodeIPMACMigration    = New("NodeIPMACMigration")
	OVSCPUPin             = New("OVSCPUPin")
	Unidle                = New("Unidle")
)

func New(name string) ginkgo.Labels {
	return label.New("Feature", name).GinkgoLabel()
}
