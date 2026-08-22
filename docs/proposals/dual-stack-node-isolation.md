# Proposal: Isolate Faulty Node Processing in Dual-Stack Clusters

## Issue Reference
- **Jira**: [OCPBUGS-81548](https://redhat.atlassian.net/browse/OCPBUGS-81548)
- **Component**: Networking / ovn-kubernetes

## Problem Statement

When adding new nodes to a dual-stack cluster, if an existing node has an invalid IPv6 configuration (link-local only), it blocks newly added nodes from becoming Ready and destabilizes OVN-Kubernetes.

### Current Behavior

1. A node with IPv6 configured as link-local only exists in a dual-stack (IPv4/IPv6) cluster
2. The faulty node's certificates are approved, but it remains NotReady with warning:
   ```
   k8s.ovn.org/node-chassis-id annotation not found
   ```
3. When another node with correct network configuration is added:
   - The new node also remains in NotReady state
   - Healthy node provisioning is blocked until the faulty node is fixed
   - `ovnkube-node` pods on control-plane nodes enter CrashLoopBackOff
   - Cluster networking becomes unstable

### Expected Behavior

1. Node with invalid IPv6 configuration should remain NotReady (expected)
2. **Newly added nodes with correct configuration should become Ready** (not happening)
3. `ovnkube-node` pods should remain stable (no crashes)
4. Faulty node should not impact other nodes joining the cluster

## Technical Analysis

### Affected Code Areas

The `k8s.ovn.org/node-chassis-id` annotation is parsed in multiple locations:

1. `go-controller/pkg/util/node_annotations.go` - `ParseNodeChassisIDAnnotation()`
2. `go-controller/pkg/ovn/master.go` - Node processing logic
3. `go-controller/pkg/ovn/zone_interconnect/zone_ic_handler.go` - Zone interconnect handling
4. `go-controller/pkg/ovn/base_network_controller.go` - Base network controller

### Root Cause Hypothesis

When processing nodes, an error from one faulty node (missing chassis-id annotation due to invalid IPv6) may be causing the controller to:
- Stop processing subsequent nodes
- Enter a crash loop trying to reconcile the faulty state
- Block the entire node join process

### Proposed Solution Areas

1. **Isolate per-node errors**: Ensure that processing errors for one node do not block processing of other nodes
2. **Graceful degradation**: Log errors for faulty nodes but continue processing healthy nodes
3. **Improved error handling**: Add specific handling for missing annotations vs. other errors

## Reproduction Steps

1. Deploy a dual-stack (IPv4/IPv6) OpenShift cluster
2. Add a node with IPv6 configured as link-local only
3. Approve the node's CSR certificates
4. Observe the node remains NotReady
5. Add another node with correct dual-stack network configuration
6. Observe that the new node is also blocked from becoming Ready

## Questions for Maintainers

1. What is the intended behavior when a node has incomplete/invalid network configuration?
2. Should node processing be isolated per-node to prevent cascade failures?
3. Are there existing patterns in the codebase for handling per-node errors gracefully?

## References

- Similar error pattern seen in zone interconnect tests: `zone_ic_handler_test.go:1441`
- Node annotation utilities: `util/node_annotations.go`
