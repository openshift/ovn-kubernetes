# OTE Test Coverage Matrix

Platform-level test coverage for upstream OVN-Kubernetes E2E tests running on
OpenShift. For infrastructure setup details (SSH, external hosts, networks),
see [infraprovider/README.md](infraprovider/README.md).

## EgressIP Tests

EgressIP tests are parameterized across 5 network types: Cluster Default,
IPv4 L2 UDN, IPv4 L3 UDN, IPv6 L2 UDN, and IPv6 L3 UDN. Each network type
runs the same set of test scenarios.

**Legend**: Y = runs, - = skipped, reason in footnotes

### Primary EgressIP (per network type, 10 tests each)

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
  label). Cluster Default variants run on GCP. Same `/32` root cause as [3].
- **[2]** Skipped on all cloud platforms. Host-networked pod tests require
  opening ports 30000-32767 on cluster nodes, not configured on bastion-based
  platforms. Can be enabled once NodePort range firewall rules are added to
  cloud platform cluster nodes.
- **[3]** Skipped on GCP for ALL network types. On GCP, nodes have `/32` primary
  interface addresses
  (`k8s.ovn.org/node-primary-ifaddr: {"ipv4":"10.0.128.x/32"}`), so
  `isOVNNetworkIP` returns false for any EgressIP, causing
  `BridgeEIPAddrManager` to skip bridge assignment and breaking IFA_PROTO
  verification. Both [1] and [3] share this single root cause and are tracked
  by [OCPBUGS-122016](https://redhat.atlassian.net/browse/OCPBUGS-122016).

### Secondary Host EIP (per network type, 8 tests each)

Baremetal only -- requires a pre-provisioned secondary network on the
hypervisor.

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

## Service Tests

Of the 37 upstream `[Feature:Service]` specs, 31 run on every platform and 6
are disabled by name in [annotate/rules.go](annotate/rules.go).

Disabled on all platforms (BM, AWS, Azure, GCP):

```
+-----------------------------------------------------------+--------+
| Disabled spec                                             | Reason |
+-----------------------------------------------------------+--------+
| Load Balancer Service Tests with MetalLB (6 specs)        | [5]    |
+-----------------------------------------------------------+--------+
```

**Footnotes**:

- **[5]** MetalLB is not deployed on any downstream lane.

Unskipping is tracked by
[CORENET-6761](https://redhat.atlassian.net/browse/CORENET-6761).

## Egress Firewall Tests

Skipped on all platforms.

Egress Firewall tests require distinct IPs for "allowed" and "denied" external
containers. On both baremetal (hypervisor with host networking) and cloud
(bastion with `--network host`), all containers share the host IP, making
CIDR-based firewall rules ineffective.

## EVPN Tests

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

## Network Segmentation (UDN) Tests

Runs on all platforms (parallel).

Excluded on `SingleReplica` topology (MicroShift, SNO) as these tests require
at least 2 nodes.

## Known Issues

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
