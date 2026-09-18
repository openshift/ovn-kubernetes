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
