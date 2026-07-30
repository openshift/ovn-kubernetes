# DPU Host No-Overlay Routing

This document describes the default-network host-to-pod routing path used
when OVN-Kubernetes runs in DPU-host mode with shared gateway mode and
`no-overlay` transport.

## Problem

In no-overlay mode, pod traffic between nodes is routed on the underlay.
On a DPU deployment, host-networked pods run on the DPU host, while the
OVN gateway router and BGP learned routes exist on the DPU.

The DPU host cannot route remote pod CIDRs through `ovn-k8s-mp0`. The
management port only reaches local node subnets. If the host keeps a broad
cluster CIDR route through the management port, host-networked pods send
remote pod traffic to the wrong place.

At the same time, the DPU host should not learn every BGP route from the
DPU. The routing decision should stay on the DPU, where OVN already has the
BGP routes.

## Datapath

The datapath uses four pieces:

1. The DPU host does not install broad default cluster CIDR routes through
   `ovn-k8s-mp0`.
2. The DPU host installs broad default cluster CIDR routes through the
   shared gateway interface using the dummy next-hop address.
3. Host nftables SNATs host-network traffic for default cluster CIDRs to
   the host masquerade IP before the packet enters OVS.
4. The DPU shared gateway bridge steers that already-SNATed traffic into
   OVN. After OVN routes it back out the default-network gateway patch, a
   higher priority bridge flow SNATs the host masquerade IP to the node
   underlay IP and sends it out the physical interface.

The first SNAT is intentionally done in host nftables, not in OpenFlow. The
bridge only matches the already-SNATed host masquerade IP when steering the
packet into OVN. This avoids double-SNAT in OpenFlow while still letting the
DPU use OVN and BGP routes for the egress decision.

## Forward Path

For host-networked pod traffic to a remote default-network pod:

1. Linux routing on the DPU host selects the shared gateway interface for
   the default cluster CIDR.
2. The host nftables postrouting rule SNATs the source to the host
   masquerade IP, for example `169.254.0.2`.
3. The DPU bridge matches:

   ```text
   in_port=<host-representor>, ip_src=<host-masquerade-ip>,
   ip_dst=<default-cluster-cidr>
   ```

   and sends the packet to the default-network OVN patch port.
4. OVN routes the packet using its logical router and BGP learned routes.
5. When the packet returns to the DPU bridge from the default-network patch
   port, the bridge matches:

   ```text
   in_port=<default-patch>, ip_src=<host-masquerade-ip>,
   ip_dst=<default-cluster-cidr>
   ```

   and commits SNAT in the default conntrack zone to the node underlay IP.
6. The packet leaves the physical interface toward the remote node or next
   hop selected by OVN routing.

## Return Path

Return traffic enters the DPU bridge from the physical interface and follows
the existing default conntrack-zone path. The bridge sends established
traffic marked for OVN back to the default-network patch port, and OVN
returns it toward the DPU host. The bridge then sends traffic destined to the
host masquerade IP through the normal OVN-to-host dispatch path, where host
conntrack reverses the nftables SNAT.

## Scope

This path is only for the default network in:

- DPU-host mode
- shared gateway mode
- no-overlay transport

It does not add host-network support for UDNs. Host-networked workloads use
the host default network, so UDN remote pod routing is outside this path.
