package container

import (
	"errors"
	"sync"

	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/api"
	"k8s.io/kubernetes/test/e2e/framework"
)

// TestContext provides a base implementation of api.Context with common container and network
// management functionality. Infrastructure providers can embed this type and override specific
// methods as needed for provider-specific behavior.
type TestContext struct {
	sync.Mutex
	*ContainerOps
	CleanUpNetworkAttachments api.Attachments
	CleanUpNetworks           api.Networks
	CleanUpContainers         []api.ExternalContainer
	CleanUpFns                []func() error
}

func (c *TestContext) CreateExternalContainer(container api.ExternalContainer) (api.ExternalContainer, error) {
	c.Lock()
	defer c.Unlock()
	container, err := c.ContainerOps.CreateExternalContainer(container)
	if err == nil {
		c.CleanUpContainers = append(c.CleanUpContainers, container)
	}
	return container, err
}

func (c *TestContext) DeleteExternalContainer(container api.ExternalContainer) error {
	c.Lock()
	defer c.Unlock()
	return c.ContainerOps.DeleteExternalContainer(container)
}

func (c *TestContext) CreateNetwork(name string, subnets ...string) (api.Network, error) {
	c.Lock()
	defer c.Unlock()
	network := ContainerEngineNetwork{NetName: name, Configs: nil}
	err := c.ContainerOps.CreateNetwork(name, subnets...)
	if err != nil {
		return network, err
	}
	c.CleanUpNetworks.InsertNoDupe(network)
	return c.ContainerOps.GetNetwork(name)
}

func (c *TestContext) AttachNetwork(network api.Network, container string) (api.NetworkInterface, error) {
	c.Lock()
	defer c.Unlock()
	err := c.ContainerOps.AttachNetwork(network, container)
	if err != nil {
		return api.NetworkInterface{}, err
	}
	c.CleanUpNetworkAttachments.InsertNoDupe(api.Attachment{Network: network, Instance: container})
	return c.ContainerOps.GetNetworkInterface(container, network.Name())
}

func (c *TestContext) DetachNetwork(network api.Network, container string) error {
	c.Lock()
	defer c.Unlock()
	return c.ContainerOps.DetachNetwork(network, container)
}

func (c *TestContext) DeleteNetwork(network api.Network) error {
	c.Lock()
	defer c.Unlock()
	return c.ContainerOps.DeleteNetwork(network)
}

func (c *TestContext) AddCleanUpFn(cleanUpFn func() error) {
	c.Lock()
	defer c.Unlock()
	c.addCleanUpFn(cleanUpFn)
}

func (c *TestContext) addCleanUpFn(cleanUpFn func() error) {
	c.CleanUpFns = append(c.CleanUpFns, cleanUpFn)
}

func (c *TestContext) CleanUp() error {
	c.Lock()
	defer c.Unlock()
	err := c.cleanUp()
	if err != nil {
		framework.Logf("Cleanup failed: %v", err)
	}
	return err
}

// CleanUp must be synchronized by caller
func (c *TestContext) cleanUp() error {
	var errs []error
	// generic cleanup activities
	for i := len(c.CleanUpFns) - 1; i >= 0; i-- {
		if err := c.CleanUpFns[i](); err != nil {
			errs = append(errs, err)
		}
	}
	c.CleanUpFns = nil
	// detach network(s) from nodes
	for _, na := range c.CleanUpNetworkAttachments.List {
		framework.Logf("Detaching network %s from %s", na.Network.Name(), na.Instance)
		if err := c.ContainerOps.DetachNetwork(na.Network, na.Instance); err != nil && !errors.Is(err, api.NotFound) {
			errs = append(errs, err)
		}
	}
	c.CleanUpNetworkAttachments.List = nil
	// remove containers
	for _, container := range c.CleanUpContainers {
		framework.Logf("Deleting container %s", container.Name)
		if err := c.ContainerOps.DeleteExternalContainer(container); err != nil && !errors.Is(err, api.NotFound) {
			errs = append(errs, err)
		}
	}
	c.CleanUpContainers = nil
	// delete secondary networks
	for _, network := range c.CleanUpNetworks.List {
		framework.Logf("Deleting network %s", network.Name())
		if err := c.ContainerOps.DeleteNetwork(network); err != nil && !errors.Is(err, api.NotFound) {
			errs = append(errs, err)
		}
	}
	c.CleanUpNetworks.List = nil
	return errors.Join(errs...)
}
