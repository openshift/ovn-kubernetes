# OVN-Kubernetes OpenShift Test Extension (OTE) - Infrastructure Provider

This document describes the test infrastructure setup for running OVN-Kubernetes
upstream E2E tests on OpenShift clusters across different platforms.

## Test Setup

The OTE infrastructure provider bridges upstream OVN-Kubernetes E2E tests with
OpenShift platform-specific infrastructure. Tests that require external
containers (e.g., EgressIP, EVPN) need a host outside the cluster to run podman
containers that act as traffic targets or routers.

### Baremetal

The hypervisor that hosts the cluster VMs also hosts external test containers
via podman. The hypervisor is directly reachable from cluster nodes on the
machine network.

```
+----------------------------+                      +------------------------+
| Hypervisor                 |                      | Cluster Nodes          |
| (SSH: root)                |                      |                        |
|                            |  ostestbm_net        | - worker-0             |
| Containers:                |  192.168.111.0/24    | - worker-1             |
|                            |  (machine network)   | - worker-2             |
| - EgressIP target (1)      |                      |                        |
|   (podman)                 |  secondarynetwork    |                        |
|                            |  10.10.10.0/24       | (secondary intf)       |
| - EgressIP target (2)      |  2001:db8:abcd::/64  |                        |
|   (podman)                 |                      |                        |
|                            |                      |                        |
| - FRR Container            |  (EVPN/BGP only)     |                        |
|   192.168.111.3            |                      |                        |
+----------------------------+                      +------------------------+
```

- **SSH access**: `root@<server-ip>` using `equinix-ssh-key` or `packet-ssh-key`
  from `CLUSTER_PROFILE_DIR`
- **Primary network**: `ostestbm_net` built from
  `Infrastructure.Spec.PlatformSpec.BareMetal.MachineNetworks`
- **Secondary network** (optional): `secondarynetwork` with subnets
  `10.10.10.0/24` and `2001:db8:abcd:1234::/64`, discovered from the hypervisor
- **Firewall**: Ports allocated for external containers (30000-32767) are opened
  via `firewall-cmd` on the hypervisor
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

1. **Machine network subnets** -- cluster node CIDRs from
   `k8s.ovn.org/node-subnets`
2. **Infrastructure network subnets** -- bastion/hypervisor host CIDRs via
   `InfrastructureNetworkExclusions()` API

On cloud platforms, without the infrastructure exclusion, the first allocated
`/20` block can overlap with the bastion host's subnet, causing L3 UDN pods to
route traffic to the bastion IP within the OVN overlay instead of externally.

## Test Coverage Matrix

### EgressIP Tests

EgressIP tests are parameterized across 5 network types: Cluster Default,
IPv4 L2 UDN, IPv4 L3 UDN, IPv6 L2 UDN, and IPv6 L3 UDN. Each network type
runs the same set of test scenarios.

**Legend**: Y = runs, - = skipped, reason in footnotes

#### Primary EgressIP (per network type, 10 tests each)

```
+----------------------------------------------+------+------+-------+------+
| Test Scenario                                | BM   | AWS  | Azure | GCP  |
+----------------------------------------------+------+------+-------+------+
| Annotation validation (user add)             | Y    | Y    | Y     | [1]  |
| Annotation validation (present at creation)  | Y    | Y    | Y     | [1]  |
| EIP reassignment on label updates            | Y    | Y    | Y     | [1]  |
| EIP logic with multiple EgressIP objects     | Y    | Y    | Y     | [1]  |
| SNAT for stateful-sets                       | Y    | Y    | Y     | [1]  |
| SNAT against host-networked pods             | Y    | [2]  | [2]   | [2]  |
| Disable egress nodes (egress-assignable)     | Y    | Y    | Y     | [3]  |
| Multiple NS sharing role primary             | Y    | Y    | Y     | [1]  |
| Multiple NS, different primary (L2 UDN)      | Y    | Y    | Y     | [3]  |
| Multiple NS, different primary (L3 UDN)      | Y    | Y    | Y     | [3]  |
+----------------------------------------------+------+------+-------+------+
```

**Footnotes**:

- **[1]** Skipped for UDN network types only (has `Feature:NetworkSegmentation`
  label). Cluster Default variants run on GCP. Caused by
  [OCPBUGS-122016](https://redhat.atlassian.net/browse/OCPBUGS-122016), can be
  enabled once fixed.
- **[2]** Skipped on all cloud platforms. Host-networked pod tests require
  opening ports 30000-32767 on cluster nodes, not configured on bastion-based
  platforms. Can be enabled once NodePort range firewall rules are added to
  cloud platform cluster nodes.
- **[3]** Skipped on GCP for ALL network types. On GCP, nodes have `/32` primary
  interface addresses
  (`k8s.ovn.org/node-primary-ifaddr: {"ipv4":"10.0.128.x/32"}`), so
  `isOVNNetworkIP` returns false for any EgressIP, causing
  `BridgeEIPAddrManager` to skip bridge assignment and breaking IFA_PROTO
  verification. Can be enabled once
  [OCPBUGS-122016](https://redhat.atlassian.net/browse/OCPBUGS-122016) is
  fixed.

#### Effective Test Count by Platform (Primary EgressIP)

```
+------------------+------+------+-------+------+
| Network Type     | BM   | AWS  | Azure | GCP  |
+------------------+------+------+-------+------+
| Cluster Default  | 10   | 9    | 9     | 6    |
| IPv4 L2 UDN      | 10   | 9    | 9     | 0    |
| IPv4 L3 UDN      | 10   | 9    | 9     | 0    |
| IPv6 L2 UDN      | 10   | 9    | 9     | 0    |
| IPv6 L3 UDN      | 10   | 9    | 9     | 0    |
+------------------+------+------+-------+------+
| Total            | 50   | 45   | 45    | 6    |
+------------------+------+------+-------+------+
```

#### Secondary Host EIP (per network type, 8 tests each)

```
+--------------------------------------------+--------+------+-------+------+
| Test Scenario                              | BM[4]  | AWS  | Azure | GCP  |
+--------------------------------------------+--------+------+-------+------+
| Traffic leak prevention (packet mark)      | Y      | -    | -     | -    |
| Multiple EgressIP objects, same intf       | Y      | -    | -     | -    |
| Disable node/pod availability              | Y      | -    | -     | -    |
| Disable node/pod availability (IPv4)       | Y      | -    | -     | -    |
| Disable node/pod avail. (IPv6 compr.)      | Y      | -    | -     | -    |
| Disable node/pod avail. (IPv6 uncompr.)    | Y      | -    | -     | -    |
| Address advertisements                     | Y      | -    | -     | -    |
| VRF routing table                          | Y      | -    | -     | -    |
+--------------------------------------------+--------+------+-------+------+
```

**[4]** Requires secondary network (`secondarynetwork` with `10.10.10.0/24` and
`2001:db8:abcd:1234::/64`) discovered on the hypervisor. Only baremetal clusters
provisioned with a secondary network run these tests.

#### Effective Test Count by Platform (Secondary Host EIP)

```
+------------------+--------+------+-------+------+
| Network Type     | BM[4]  | AWS  | Azure | GCP  |
+------------------+--------+------+-------+------+
| Cluster Default  | 8      | 0    | 0     | 0    |
| IPv4 L2 UDN      | 8      | 0    | 0     | 0    |
| IPv4 L3 UDN      | 8      | 0    | 0     | 0    |
| IPv6 L2 UDN      | 8      | 0    | 0     | 0    |
| IPv6 L3 UDN      | 8      | 0    | 0     | 0    |
+------------------+--------+------+-------+------+
| Total            | 40     | 0    | 0     | 0    |
+------------------+--------+------+-------+------+
```

### Skipped EgressIP Test Categories

These EgressIP tests are not enabled on any platform:

```
+----------------------+----------------------------------------------------------------+
| Test Category        | Reason                                                         |
+----------------------+----------------------------------------------------------------+
| GRPC health check    | DaemonSet env var change cascades into multus CrashLoopBackOff |
| Legacy health check  | iptables DROP on port 9 not effective on OpenShift             |
| Node readiness       | oc debug pod killed when kubelet stops on target node          |
| MTU fragmentation    | podman disallows net-ns sysctls with --network host            |
+----------------------+----------------------------------------------------------------+
```

### Egress Firewall Tests

Skipped on all platforms.

Egress Firewall tests require distinct IPs for "allowed" and "denied" external
containers. On both baremetal (hypervisor with host networking) and cloud
(bastion with `--network host`), all containers share the host IP, making
CIDR-based firewall rules ineffective.

### EVPN Tests

```
+----------+----------------------------------------+
| Platform | Status                                 |
+----------+----------------------------------------+
| BareMetal| Runs when EVPN prerequisites are met   |
| AWS      | Skipped (no FRR container)             |
| Azure    | Skipped (no FRR container)             |
| GCP      | Skipped (no FRR container)             |
+----------+----------------------------------------+
```

**Prerequisites** (all must be true):
- `EVPN` feature gate enabled in cluster
- FRR configured as routing capability provider
- Local gateway mode (routing via host)
- FRR external container available on the hypervisor

### Network Segmentation (UDN) Tests

Runs on all platforms (parallel).

Excluded on `SingleReplica` topology (MicroShift, SNO) as these tests require
at least 2 nodes.

## Platform Summary

```
+----------------------------+------+--------+------+-------+------+
| Metric                     | BM   | BM+Sec | AWS  | Azure | GCP  |
+----------------------------+------+--------+------+-------+------+
| Primary EgressIP tests     | 50   | 50     | 45   | 45    | 6    |
| Secondary Host EIP tests   | 0    | 40     | 0    | 0     | 0    |
| Egress Firewall tests      | 0    | 0      | 0    | 0     | 0    |
| EVPN tests (when enabled)  | 43   | 43     | 0    | 0     | 0    |
| Network Segmentation tests | 63   | 63     | 63   | 63    | 63   |
+----------------------------+------+--------+------+-------+------+
```

## Known Issues and Caveats

### GCP: /32 Node Primary Interface (OCPBUGS-122016)

On GCP, node primary interface addresses use a `/32` prefix mask:

```
k8s.ovn.org/node-primary-ifaddr: '{"ipv4":"10.0.128.3/32"}'
```

This causes `isOVNNetworkIP()` to return `false` for any EgressIP, because a
`/32` network contains only the node's own IP. As a result,
`BridgeEIPAddrManager` skips assigning EgressIPs to the OVS bridge interface,
breaking IFA_PROTO verification and all UDN EgressIP tests.

### Cloud Platforms: Shared Container IP

All external containers on cloud platforms share the bastion host's IP via
`--network host`. This prevents:
- Egress Firewall tests (can't distinguish containers by IP)
- Any test requiring multiple external containers with different IPs

### Cloud Platforms: Host-Networked Pod Tests

EgressIP tests against host-networked pods require opening NodePort range
(30000-32767) on cluster nodes via firewall rules. This is not yet configured
on bastion-based cloud platforms.

### UDN Subnet Overlap with Bastion Network

Without `InfrastructureNetworkExclusions`, the UDN allocator's first free `/20`
block can land in the bastion's subnet:
- **AWS**: Nodes in `10.0.0.0/18`, first free `/20` = `10.0.64.0/20`, bastion
  at `10.0.74.x/18` overlaps
- **Azure**: Nodes in `10.0.0.0/17` + `10.0.128.0/17`, first free `/20` =
  `10.1.0.0/20`, bastion at `10.1.0.x` overlaps

The `InfrastructureNetworkExclusions` API excludes the bastion host's subnet
CIDR from UDN allocations, preventing this overlap. On baremetal, the hypervisor
is on the same machine network as nodes, so no additional exclusion is needed.
