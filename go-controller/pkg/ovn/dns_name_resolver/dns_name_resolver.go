package dnsnameresolver

import (
	addressset "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/address_set"
)

type DNSNameResolver interface {
	Add(namespace, dnsName string) (addressset.AddressSet, error)
	Delete(namespace string) error
	Run() error
	Shutdown()
}
