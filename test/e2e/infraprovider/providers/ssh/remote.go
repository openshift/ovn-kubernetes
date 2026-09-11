// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package ssh

import (
	"fmt"

	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/api"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/container"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/testcontext"
)

// RemoteContainerInfra is the reusable substrate for driving a container runtime
// on a remote host over SSH. It owns the api.Runner and the container.Engine and
// implements the external-container/network surface (api.ExternalContainerProvider).
//
// It knows nothing about Kubernetes, node exec, or provider selection. Both the
// standalone Provider and a composing provider can build on it: a composing
// provider can embed it to inherit external-container behavior while supplying
// its own cluster-side behavior.
type RemoteContainerInfra struct {
	runtime string
	runner  api.Runner
	engine  *container.Engine
}

// NewRemoteContainerInfra builds a RemoteContainerInfra from cfg using the
// provided runner. The runner is injectable so unit tests can supply a fake and
// callers can supply an already-constructed SSH runner. Most callers should use
// New (in provider.go), which constructs the SSH runner from
// cfg for them.
//
// It validates the one field it actually uses (Runtime) and rejects a nil runner,
// so an invalid/zero Config or a nil runner fails fast at construction rather than
// panicking on first use. It does NOT require the SSH connection fields
// (Host/User/Port/Key): those are only used by New to build the runner, which the
// caller has already supplied here.
func NewRemoteContainerInfra(cfg Config, runner api.Runner) (*RemoteContainerInfra, error) {
	cfg.applyDefaults()
	if err := cfg.checkRuntime(); err != nil {
		return nil, err
	}
	if runner == nil {
		return nil, fmt.Errorf("ssh: RemoteContainerInfra requires a non-nil runner")
	}
	return &RemoteContainerInfra{
		runtime: cfg.Runtime,
		runner:  runner,
		engine:  container.NewEngine(cfg.Runtime, runner),
	}, nil
}

// Engine exposes the underlying container engine. It is primarily useful for a
// composing provider that needs to drive node-as-container operations (e.g.
// ShutdownNode) over the same runner.
func (r *RemoteContainerInfra) Engine() *container.Engine {
	return r.engine
}

// Close releases the underlying SSH connection if the runner supports it. It is
// safe to call on runners that do not implement io.Closer.
func (r *RemoteContainerInfra) Close() error {
	if closer, ok := r.runner.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}

// --- api.ExternalContainerProvider (no per-test context required) ---

func (r *RemoteContainerInfra) ListNetworks() ([]string, error) {
	return r.engine.ListNetworks()
}

func (r *RemoteContainerInfra) GetNetwork(name string) (api.Network, error) {
	return r.engine.GetNetwork(name)
}

func (r *RemoteContainerInfra) GetExternalContainerNetworkInterface(c api.ExternalContainer, network api.Network) (api.NetworkInterface, error) {
	return r.engine.GetExternalContainerNetworkInterface(c, network)
}

func (r *RemoteContainerInfra) ExecExternalContainerCommand(c api.ExternalContainer, cmd []string) (string, error) {
	return r.engine.ExecExternalContainerCommand(c, cmd)
}

func (r *RemoteContainerInfra) GetExternalContainerLogs(c api.ExternalContainer) (string, error) {
	return r.engine.GetExternalContainerLogs(c)
}

func (r *RemoteContainerInfra) GetExternalContainerPort() uint16 {
	return r.engine.GetExternalContainerPort()
}

func (r *RemoteContainerInfra) ExternalContainerPrimaryInterfaceName() string {
	return r.engine.ExternalContainerPrimaryInterfaceName()
}

// NewExternalContainerContext returns a per-test-scoped view of the external
// container operations. Create/Attach operations register their cleanup on the
// supplied TestContext, mirroring the kind provider's behavior.
func (r *RemoteContainerInfra) NewExternalContainerContext(tc *testcontext.TestContext) *RemoteContainerContext {
	return &RemoteContainerContext{engine: r.engine.WithTestContext(tc)}
}

// RemoteContainerContext is a per-test-scoped implementation of
// api.ExternalContainerContextProvider backed by a context-bound container.Engine.
type RemoteContainerContext struct {
	engine *container.Engine
}

func (c *RemoteContainerContext) CreateNetwork(name string, subnets ...string) (api.Network, error) {
	return c.engine.CreateNetwork(name, subnets...)
}

func (c *RemoteContainerContext) DeleteNetwork(network api.Network) error {
	return c.engine.DeleteNetwork(network)
}

func (c *RemoteContainerContext) CreateExternalContainer(container api.ExternalContainer) (api.ExternalContainer, error) {
	return c.engine.CreateExternalContainer(container)
}

func (c *RemoteContainerContext) DeleteExternalContainer(container api.ExternalContainer) error {
	return c.engine.DeleteExternalContainer(container)
}

func (c *RemoteContainerContext) AttachNetwork(network api.Network, instance string) (api.NetworkInterface, error) {
	return c.engine.AttachNetwork(network, instance)
}

func (c *RemoteContainerContext) DetachNetwork(network api.Network, instance string) error {
	return c.engine.DetachNetwork(network, instance)
}
