# OTE Infrastructure Provider

Provides platform-specific test infrastructure (external hosts, networks, SSH)
for running upstream OVN-Kubernetes E2E tests on OpenShift clusters.

For test coverage matrix and platform skip reasons, see
[test/README.md](../README.md).

## Test Setup

Tests that require external containers (e.g., EgressIP, EVPN) need a host
outside the cluster to run podman containers that act as traffic targets or
routers.

### Baremetal

The hypervisor that hosts the cluster VMs also hosts external test containers
via podman. The hypervisor is directly reachable from cluster nodes on the
machine network.

```
+----------------------------+                           +------------------------+
| Hypervisor                 |                           | Cluster Nodes          |
| (SSH: root)                |                           |                        |
|                            |  ostestbm_net             | - worker-0             |
| Containers:                |  192.168.111.0/24         | - worker-1             |
|                            |  (machine network)        | - worker-2             |
| - EgressIP target (1)      |                           |                        |
|   (podman)                 |  secondarynetwork         |                        |
|                            |  10.10.10.0/24            | (secondary intf)       |
| - EgressIP target (2)      |  2001:db8:abcd:1234::/64  |                        |
|   (podman)                 |                           |                        |
|                            |                           |                        |
| - FRR Container            |  (EVPN/BGP only)          |                        |
|   192.168.111.3            |                           |                        |
+----------------------------+                           +------------------------+
```

- **SSH access**: `root@<server-ip>` using `equinix-ssh-key` or `packet-ssh-key`
  from `CLUSTER_PROFILE_DIR`
- **Primary network**: `ostestbm_net` built from
  `Infrastructure.Spec.PlatformSpec.BareMetal.MachineNetworks`
- **Secondary network** (optional): `secondarynetwork` with subnets
  `10.10.10.0/24` and `2001:db8:abcd:1234::/64`, discovered from the hypervisor
- **Firewall**: Port range 12000-65535/tcp is opened via `firewall-cmd` on the
  hypervisor for external container traffic
- **IP forwarding**: Enabled on secondary interfaces of cluster nodes when a
  secondary network is discovered

#### Isolated External Containers

Some specs need external containers with their own IP and MAC on the machine
network, and change the container's MAC or take its link down, which host
networking can't provide safely. Primary-network containers whose name is
listed in `isolatedContainerNames` are therefore not host-networked:
`baremetal_isolated.go` creates them through the normal container engine
(`podman run` with `--ip`/`--ip6`, cleanup with the test context) on a
dedicated network. All other containers keep the host-networked behaviour.

- **Addresses**: the e2e primary IP allocator (`test/e2e/allocators/
  ipalloc.go`), which the other specs already use for machine-network
  addresses: its reserved per-node range (`.200`-`.254` / `::c8`-`::ff` by
  default), handed out per test process and checked against the node host
  addresses (`k8s.ovn.org/host-cidrs`). The fixture only turns the allocated
  IPs into `--ip`/`--ip6`. Like the allocator's other users, it relies on the
  lane's dev-scripts profile to keep that range free.
- **Network**: `ovnk-e2e-isolated`, a podman network that plugs containers
  into the existing machine network bridge (`ostestbm` on dev-scripts, found at
  provider initialisation). It is never `ostestbm_net`, which belongs to the BGP
  setup. It's created once, when missing, with:
  - `--opt mode=unmanaged`: podman only attaches the containers. In its
    default (managed) mode it would set the hypervisor up around the bridge:
    a gateway address on the bridge, firewall/NAT rules and forwarding sysctls.
    The bridge belongs to libvirt and must stay as libvirt configured it;
  - `--opt no_default_route=true`: the containers only talk to the machine
    subnet, so they need no gateway (none is passed);
  - `--disable-dns`: no podman DNS server next to libvirt's dnsmasq;
  - the machine subnets, so the allocated addresses fit.

### Cloud Platforms (AWS, Azure, GCP)

A bastion host in the same VPC runs external test containers via podman with
`--network host`. All containers share the bastion's IP address.

```
+----------------------------+                      +------------------------+
| Bastion Host               |                      | Cluster Nodes          |
| (SSH: core)                |                      |                        |
| (sudo podman)              |  VPC network         | - worker-0             |
|                            |  (host networking)   | - worker-1             |
| Containers:                |                      | - worker-2             |
| - EgressIP targets         |                      |                        |
|   (podman --net=host)      |                      |                        |
|                            |                      |                        |
| All containers share       |                      |                        |
| bastion host IP            |                      |                        |
+----------------------------+                      +------------------------+
```

- **SSH access**: `<bastion_ssh_user>@<bastion_public_address>` using
  `ssh-privatekey` from `CLUSTER_PROFILE_DIR`
- **Podman**: Runs under `sudo` because the SSH user (`core`) is unprivileged;
  rootless containers exit when the SSH session terminates
- **Primary network**: `host` -- containers attach to the bastion's host network.
  The bastion's default-route interface is discovered via
  `ip -j route show default`
- **No secondary network**: `secondary-host-eip` tests are not supported
- **Shared IP**: All containers share the bastion's host IP, which limits tests
  that require distinct container IPs (e.g., Egress Firewall CIDR rules)

### Localnet Underlay

The localnet MAC-security tests use `SetupUnderlay` to map the test's logical
network to the existing external OVS bridge, `br-ex`, on every node. No
dedicated OVS bridge, physical NIC, or external container is created.

The **kubernetes-nmstate operator and its CRDs must already be installed**,
including `NMState`, `NodeNetworkConfigurationPolicy` (NNCP), and
`NodeNetworkConfigurationEnactment` (NNCE). The test identity needs permission
to create, read, and patch NMState and NNCP resources, delete NNCPs, read
NNCEs, and list Nodes.

The setup and cleanup lifecycle is:

1. `nmstate.Deploy` creates or patches the `NMState` resource named `nmstate`
   and waits for it to become Available. It does **not** install the operator
   or its CRDs.
2. `SetupUnderlay` creates or patches an NNCP named after the test framework's
   unique name, adding the logical-network-to-`br-ex` bridge mapping.
3. Setup waits for the NNCP to become Available and for every selected node's
   NNCE to report Available for the written policy generation.
4. When the test context is cleaned up, the mapping is first marked `absent`
   in the NNCP and the helper waits for that update to be applied. Only after
   removal succeeds does it delete the NNCP and wait for it to disappear.
   Deleting an NNCP alone does not undo the applied network configuration.
   The NMState resource and operator are left in place.

If mapping removal fails, cleanup returns an error identifying the NNCP and
does not delete it. Inspect the policy and its per-node NNCEs, resolve the
node or NMState failure, and retry mapping removal before deleting the policy.
If the update failed before being persisted, the policy might still request
the mapping to be present; ensure it requests `absent` first. Retaining the
policy preserves the desired state for recovery but does not guarantee
automatic retries. Delete it only after every selected node's NNCE reports
Available for the policy's removal generation.

The helpers bound the complete operation, including API writes and polling:
five minutes for NMState deployment and one minute for each NNCP update or
deletion. Earlier caller deadlines are preserved, and each cleanup operation
receives a fresh budget.

Run these tests through `ovn-kubernetes/conformance/serial/virtualization`,
whose `Parallelism: 1` setting prevents the fixed VLAN and IP configuration
from overlapping between tests. A `[Serial]` label in a test name alone does
not serialize execution by the extension runner.

### UDN Subnet Allocation

The UDN subnet allocator (`test/e2e/allocators/udn.go`) allocates `/20` blocks
from `10.0.0.0/10` for L3 User Defined Networks. It excludes:

1. **Machine network subnets** -- node CIDRs from the cloud egress IP
   annotation (`cloud-network-config-controller`), falling back to
   `k8s.ovn.org/node-primary-ifaddr` on baremetal
2. **Infrastructure network subnets** -- bastion/hypervisor host CIDRs via
   `InfrastructureNetworkExclusions()` API

On cloud platforms, without the infrastructure exclusion, the first allocated
`/20` block can overlap with the bastion host's subnet, causing L3 UDN pods to
route traffic to the bastion IP within the OVN overlay instead of externally.
