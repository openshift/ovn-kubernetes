// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package ssh

import (
	"fmt"

	"github.com/onsi/ginkgo/v2"

	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/api"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/portalloc"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/runner"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/engine/testcontext"
	"k8s.io/kubernetes/test/e2e/framework"
)

// Compile-time interface assertions.
var (
	_ api.Provider = (*Provider)(nil)
	_ api.Context  = (*providerContext)(nil)
)

// Provider is the standalone, vendor-neutral SSH infra provider. It drives the
// container runtime on a remote host over SSH (via RemoteContainerInfra) for all
// external-container/network work, and executes node commands through a pluggable
// NodeExecutor.
type Provider struct {
	cfg      Config
	remote   *RemoteContainerInfra
	hostPort *portalloc.PortAllocator
	nodeExec NodeExecutor
}

// New constructs a Provider from cfg, building the SSH runner from the config's
// connection fields. If cfg.NodeExecutor is nil it defaults to an engine-based
// executor (container runtime "exec" over SSH), suitable for the upstream
// kind-over-ssh guardrail.
func New(cfg Config) (*Provider, error) {
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	sshRunner, err := runner.NewSSHRunner(cfg.Host, cfg.User, cfg.Port, cfg.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create ssh runner for %s@%s: %w", cfg.User, cfg.Host, err)
	}
	remote, err := NewRemoteContainerInfra(cfg, sshRunner)
	if err != nil {
		return nil, err
	}
	nodeExec := cfg.NodeExecutor
	if nodeExec == nil {
		nodeExec = NewEngineNodeExecutor(remote.Engine())
	}
	p := &Provider{
		cfg:      cfg,
		remote:   remote,
		hostPort: portalloc.New(1024, 65535),
		nodeExec: nodeExec,
	}
	framework.Logf("ssh infra provider ready (host %q, runtime %q): SMOKE/SUBSET provider; "+
		"unsupported capabilities %v must be excluded from this lane", cfg.Host, cfg.Runtime,
		p.UnsupportedCapabilities())
	return p, nil
}

// Close releases the provider's SSH connection. Intended to be called once at
// suite teardown (see TestMain). Per-test cleanup does NOT close it, because the
// cached SSH client is reused across tests for the life of the suite.
func (p *Provider) Close() error {
	return p.remote.Close()
}

// UnsupportedCapabilities lists api.Provider capabilities this provider does not
// implement, so the lane wiring can exclude the specs that depend on them (today:
// SetupUnderlay). It is the machine-readable half of the "SMOKE/SUBSET" contract
// that New logs at construction.
func (p *Provider) UnsupportedCapabilities() []string {
	return []string{"SetupUnderlay"}
}

// --- api.ClusterProvider ---

func (p *Provider) Name() string {
	return "ssh"
}

func (p *Provider) PrimaryNetwork() (api.Network, error) {
	return p.remote.GetNetwork(p.cfg.PrimaryNetwork)
}

func (p *Provider) GetK8NodeNetworkInterface(instance string, network api.Network) (api.NetworkInterface, error) {
	// In the kind-over-ssh model a node is a container on the same daemon, so we
	// can read its interface via the engine (container inspect over SSH), exactly
	// as the kind provider does locally.
	ni, err := p.remote.Engine().GetNetworkInterface(instance, network.Name())
	if err != nil {
		return ni, fmt.Errorf("get network interface for node %q on network %q: %w", instance, network.Name(), err)
	}
	return ni, nil
}

func (p *Provider) ExecK8NodeCommand(nodeName string, cmd []string) (string, error) {
	out, err := p.nodeExec.Exec(nodeName, cmd)
	if err != nil {
		return out, fmt.Errorf("exec command on node %q: %w", nodeName, err)
	}
	return out, nil
}

func (p *Provider) GetK8HostPort() uint16 {
	return p.hostPort.Allocate()
}

// ShutdownNode and StartNode treat a node as a container on the (remote) engine
// (`<runtime> stop|start <node>`). This is valid ONLY when cluster nodes are
// containers whose names equal the Kubernetes node names — true for the upstream
// kind-over-ssh guardrail. A consumer whose nodes are VMs must NOT use this
// provider's node lifecycle methods (they would issue a meaningless `docker
// stop`); such consumers supply their own ClusterProvider behavior.
func (p *Provider) ShutdownNode(nodeName string) error {
	if err := p.remote.Engine().StopContainer(nodeName); err != nil {
		return fmt.Errorf("shutdown node %q: %w", nodeName, err)
	}
	return nil
}

func (p *Provider) StartNode(nodeName string) error {
	if err := p.remote.Engine().StartContainer(nodeName); err != nil {
		return fmt.Errorf("start node %q: %w", nodeName, err)
	}
	return nil
}

// PreloadImages delegates to Config.ImagePreloader when set. When it is not set
// this performs NO preloading and warns loudly: the SSH lane then requires images
// to be made available out of band (e.g. `kind load` in CI). It deliberately does
// not silently report success.
func (p *Provider) PreloadImages(images []string) {
	if p.cfg.ImagePreloader != nil {
		if err := p.cfg.ImagePreloader(images); err != nil {
			framework.Logf("ssh provider: ImagePreloader failed for %d image(s): %v", len(images), err)
		}
		return
	}
	framework.Logf("WARNING: ssh provider does NOT preload images (%d requested). This lane REQUIRES "+
		"images to be loaded into the cluster out of band (e.g. `kind load`), or specs may fail on "+
		"image pull. Set Config.ImagePreloader to preload.", len(images))
}

func (p *Provider) GetDefaultTimeoutContext() *framework.TimeoutContext {
	return framework.NewTimeoutContext()
}

// --- api.ExternalContainerProvider (delegated to the remote substrate) ---

func (p *Provider) ListNetworks() ([]string, error) {
	return p.remote.ListNetworks()
}

func (p *Provider) GetNetwork(name string) (api.Network, error) {
	return p.remote.GetNetwork(name)
}

func (p *Provider) GetExternalContainerNetworkInterface(c api.ExternalContainer, network api.Network) (api.NetworkInterface, error) {
	return p.remote.GetExternalContainerNetworkInterface(c, network)
}

func (p *Provider) ExecExternalContainerCommand(c api.ExternalContainer, cmd []string) (string, error) {
	return p.remote.ExecExternalContainerCommand(c, cmd)
}

func (p *Provider) GetExternalContainerLogs(c api.ExternalContainer) (string, error) {
	return p.remote.GetExternalContainerLogs(c)
}

func (p *Provider) GetExternalContainerPort() uint16 {
	return p.remote.GetExternalContainerPort()
}

func (p *Provider) ExternalContainerPrimaryInterfaceName() string {
	return p.remote.ExternalContainerPrimaryInterfaceName()
}

// --- api.Provider ---

func (p *Provider) NewTestContext() api.Context {
	tc := &testcontext.TestContext{}
	ginkgo.DeferCleanup(tc.CleanUp)
	return &providerContext{
		TestContext: tc,
		external:    p.remote.NewExternalContainerContext(tc),
	}
}

// providerContext is the per-test sandbox. External-container operations are
// delegated to a context-bound RemoteContainerContext so their cleanup is
// registered on the test context.
type providerContext struct {
	*testcontext.TestContext
	external *RemoteContainerContext
}

func (c *providerContext) CreateNetwork(name string, subnets ...string) (api.Network, error) {
	return c.external.CreateNetwork(name, subnets...)
}

func (c *providerContext) DeleteNetwork(network api.Network) error {
	return c.external.DeleteNetwork(network)
}

func (c *providerContext) CreateExternalContainer(container api.ExternalContainer) (api.ExternalContainer, error) {
	return c.external.CreateExternalContainer(container)
}

func (c *providerContext) DeleteExternalContainer(container api.ExternalContainer) error {
	return c.external.DeleteExternalContainer(container)
}

func (c *providerContext) AttachNetwork(network api.Network, instance string) (api.NetworkInterface, error) {
	return c.external.AttachNetwork(network, instance)
}

func (c *providerContext) DetachNetwork(network api.Network, instance string) error {
	return c.external.DetachNetwork(network, instance)
}

// SetupUnderlay is not yet supported by the generic ssh provider: the kind
// implementation depends on unexported OVS pod-exec helpers in the kind package.
// Lifting those into a shared, provider-agnostic package is a planned fast-follow;
// until then specs that call SetupUnderlay must be excluded from the ssh lane.
func (c *providerContext) SetupUnderlay(_ *framework.Framework, _ api.Underlay) error {
	return fmt.Errorf("SetupUnderlay: %w", ErrUnsupported)
}
