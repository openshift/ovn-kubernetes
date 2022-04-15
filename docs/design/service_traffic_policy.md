# Kubernetes Service Traffic Policy Implementation


## External Traffic Policy

For [Kubernetes Services](https://kubernetes.io/docs/concepts/services-networking/service/) of type Nodeport or
Loadbalancer a user can set the `service.spec.externalTrafficPolicy` field to either `cluster` or `local` to denote
whether or not external traffic is routed to cluster-wide or node-local endpoints. The default value for the
`externalTrafficPolicy` field is `cluster`. In this configuration in ingress traffic is equally disributed across all
backends and the original client IP address is lost due to SNAT. If set to `local` then the client
source IP is preserved throughout the service flow and if service traffic arrives at nodes without
local endpoints it gets dropped. See [sources](#sources) for more information on ETP=local.

Setting an `ExternalTrafficPolicy` to `Local` is only allowed for Services of type `NodePort` or `LoadBalancer`. The
APIServer enforces this requirement.

## Implementing `externalTrafficPolicy` In OVN-Kubernetes

To properly implement this feature for all relevant traffic flows, required changing how OVN, Iptables rules, and
Physical OVS flows are updated and managed in OVN-Kubernetes

## ExternalTrafficPolicy=Local

### OVN Load_Balancer configuration

Normally, each service in Kubernetes has a corresponding single Load_Balancer row created in OVN. This LB is attached
to all node switches and gateway routers (GWRs). ExternalTrafficPolicy creates multiple LBs, however.

Specifically, different load balancers are attached to switches versus routers. The node switch LBs handle traffic from pods,
whereas the gateway router LBs handle external traffic.

Thus, an additional LB is created with the `skip_snat="true"` option and is applied to the GatewayRouters
and Worker switches. It is needed to override the `lb_force_snat_ip=router_ip` option that is on all the Gateway Routers,
which allows ingress traffic to arrive at OVN managed endpoints with the original client IP.

All externally-accessible vips (NodePort, ExternalIPs, LoadBalancer Status IPs) for services with `externalTrafficPolicy:local`
will reside on this loadbalancer. The loadbalancer backends may be empty, depending on whether there are pods local
to that node.

### Handling Flows between the overlay and underlay

In this section we will look at some relevant traffic flows when a service's `externalTrafficPolicy` is `local`.  For
these examples we will be using a Nodeport service, but the flow is generally the same for ExternalIP and Loadbalancer
type services.

### Ingress Traffic

This section will cover the networking entities hit when traffic ingresses a cluster via a service to either host
networked pods or cluster networked pods. If its host networked pods, then the traffic flow is the same on both gateway modes. If its cluster networked pods, they will be different for each mode.

### External Source -> Service -> OVN pod

#### **Shared Gateway Mode**

This case is the same as normal shared gateway traffic ingress, meaning the externally sourced traffic is routed into
OVN via flows on breth0, except in this case the new local load balancer is hit on the GR, which ensures the ip of the
client is preserved  by the time it gets to the destination Pod.

```text
          host (ovn-worker, 172.18.0.3) 
           |
eth0--->|breth0| -----> 172.18.0.3 OVN GR 100.64.0.4 --> join switch --> ovn_cluster_router --> 10.244.1.3 pod

```

#### **Local Gateway Mode**

The implementation of this case differs for local gateway from that for shared gateway. In local gateway if the above path is used, response traffic would be assymmetric since the default route for pod egress traffic is via `ovn-k8s-mp0`.

In local gateway mode, rather than sending the traffic from breth0 into OVN via gateway router, we use flows on breth0 to send it into the host.

```text
          host (ovn-worker, 172.18.0.3) ---- 172.18.0.3 LOCAL(host) -- iptables -- ovn-k8s-mp0 -- node-local-switch -- 10.244.1.3 pod
           ^
           ^
           |
eth0--->|breth0|

```

1. Match on the incoming traffic via default flow on `table0`, send it to `table1`:

```
cookie=0xdeff105, duration=3189.786s, table=0, n_packets=99979, n_bytes=298029215, priority=50,ip,in_port=eth0 actions=ct(table=1,zone=64000)
```

2. Send it out to LOCAL ovs port on breth0 and traffic is delivered to the host:

```
cookie=0xdeff105, duration=3189.787s, table=1, n_packets=108, n_bytes=23004, priority=0 actions=NORMAL
```

3. In the host, we have an IPtable rule in the PREROUTING chain that DNATs this packet matched on nodePort to a masqueradeIP (169.254.169.3) used specially for this traffic flow.

```
[3:180] -A OVN-KUBE-ETP -p tcp -m addrtype --dst-type LOCAL -m tcp --dport 31746 -j DNAT --to-destination 169.254.169.3:31746
```

4. The special masquerade route in the host sends this packet into OVN via the management port.

```
169.254.169.3 via 10.244.0.1 dev ovn-k8s-mp0 
```

5. Since by default, all traffic into `ovn-k8s-mp0` gets SNAT-ed, we add an IPtable rule to `OVN-KUBE-SNAT-MGMTPORT` chain to ensure it doesn't get SNAT-ed to preserve its source-ip.

```
[3:180] -A OVN-KUBE-SNAT-MGMTPORT -p tcp -m tcp --dport 31746 -j RETURN
```

6. Traffic enters the node local switch on the worker node and hits the load-balancer where we add a new vip for this masqueradeIP to DNAT it correctly to the local backends. Note that this vip will translate only to the backends that are local to that worker node and hence traffic will be rejected if there is no local endpoint thus respecting ETP=local type traffic rules.

The switch load-balancer on a node with local endpoints will look like this:

```
_uuid               : b3201caf-3089-4462-b96e-1406fd7c4256
external_ids        : {"k8s.ovn.org/kind"=Service, "k8s.ovn.org/owner"="default/example-service-1"}
health_check        : []
ip_port_mappings    : {}
name                : "Service_default/example-service-1_TCP_node_switch_ovn-worker2"
options             : {event="false", reject="true", skip_snat="false"}
protocol            : tcp
selection_fields    : []
vips                : {"169.254.169.3:31746"="10.244.1.3:8080", "172.18.0.3:31746"="10.244.1.3:8080,10.244.2.3:8080"}
```

The switch load-balancer on a node without local endpoints will look like this:
```
_uuid               : 42d75e10-5598-4197-a6f2-1a37094bee13
external_ids        : {"k8s.ovn.org/kind"=Service, "k8s.ovn.org/owner"="default/example-service-1"}
health_check        : []
ip_port_mappings    : {}
name                : "Service_default/example-service-1_TCP_node_switch_ovn-worker"
options             : {event="false", reject="true", skip_snat="false"}
protocol            : tcp
selection_fields    : []
vips                : {"169.254.169.3:31746"="", "172.18.0.4:31746"="10.244.1.3:8080,10.244.2.3:8080"}
```

Response traffic will follow the same path (backend->node switch->mp0->host->breth0->eth0).

7. Return traffic gets matched on default flow in `table0` and it sent out via default interface back to the external source.

```
cookie=0xdeff105, duration=12994.192s, table=0, n_packets=47706, n_bytes=3199460, idle_age=0, priority=100,ip,in_port=LOCAL actions=ct(commit,zone=64000,exec(load:0x2->NXM_NX_CT_MARK[])),output:1
```

The conntrack state looks like this:
```
    [NEW] tcp      6 120 SYN_SENT src=172.18.0.1 dst=172.18.0.3 sport=36366 dport=31746 [UNREPLIED] src=169.254.169.3 dst=172.18.0.1 sport=31746 dport=36366
    [NEW] tcp      6 120 SYN_SENT src=172.18.0.1 dst=169.254.169.3 sport=36366 dport=31746 [UNREPLIED] src=10.244.1.3 dst=172.18.0.1 sport=8080 dport=36366 zone=9
    [NEW] tcp      6 120 SYN_SENT src=172.18.0.1 dst=10.244.1.3 sport=36366 dport=8080 [UNREPLIED] src=10.244.1.3 dst=172.18.0.1 sport=8080 dport=36366 zone=11
 [UPDATE] tcp      6 60 SYN_RECV src=172.18.0.1 dst=172.18.0.3 sport=36366 dport=31746 src=169.254.169.3 dst=172.18.0.1 sport=31746 dport=36366
 [UPDATE] tcp      6 432000 ESTABLISHED src=172.18.0.1 dst=172.18.0.3 sport=36366 dport=31746 src=169.254.169.3 dst=172.18.0.1 sport=31746 dport=36366 [ASSURED]
    [NEW] tcp      6 300 ESTABLISHED src=172.18.0.3 dst=172.18.0.1 sport=31746 dport=36366 [UNREPLIED] src=172.18.0.1 dst=172.18.0.3 sport=36366 dport=31746 mark=2 zone=64000
 [UPDATE] tcp      6 120 FIN_WAIT src=172.18.0.1 dst=172.18.0.3 sport=36366 dport=31746 src=169.254.169.3 dst=172.18.0.1 sport=31746 dport=36366 [ASSURED]
 [UPDATE] tcp      6 30 LAST_ACK src=172.18.0.1 dst=172.18.0.3 sport=36366 dport=31746 src=169.254.169.3 dst=172.18.0.1 sport=31746 dport=36366 [ASSURED]
 [UPDATE] tcp      6 120 TIME_WAIT src=172.18.0.1 dst=172.18.0.3 sport=36366 dport=31746 src=169.254.169.3 dst=172.18.0.1 sport=31746 dport=36366 [ASSURED]
```


### External Source -> Service -> Host Networked pod

This Scenario is a bit different, specifically traffic now needs to be directed from an external source to service and
then to the host itself (a host networked pod)

In this flow, rather than going from breth0 into OVN we shortcircuit the path with physical flows on breth0. This is the same for both the gateway modes.

```text
          host (ovn-worker, 172.18.0.3) 
           ^
           ^
           |
eth0--->|breth0| ---- 172.18.0.3 OVN GR 100.64.0.4 -- join switch -- ovn_cluster_router -- 10.244.1.3 pod

```

1. Match on the incoming traffic via it's nodePort, DNAT directly to the host networked endpoint, and send to `table=6`

```
cookie=0x790ba3355d0c209b, duration=153.288s, table=0, n_packets=18, n_bytes=1468, idle_age=100, priority=100,tcp,in_port=1,tp_dst=<nodePort> actions=ct(commit,table=6,zone=64003,nat(dst=<nodeIP>:<targetIP>))
```

2. Send out the LOCAL ovs port on breth0, and traffic is delivered to host netwoked pod

```
cookie=0x790ba3355d0c209b, duration=113.033s, table=6, n_packets=18, n_bytes=1468, priority=100 actions=LOCAL
```

3. Return traffic from the host networked pod to external source is matched in `table=7` based on the src_ip of the return
   traffic being equal to `<targetIP>`, and un-Nat back to `<nodeIP>:<NodePort>`

```
 cookie=0x790ba3355d0c209b, duration=501.037s, table=0, n_packets=12, n_bytes=1259, idle_age=448, priority=100,tcp,in_port=LOCAL,tp_src=<targetIP> actions=ct(commit,table=7,zone=64003,nat)
```

4. Send the traffic back out breth0 back to the external source in `table=7`

```
cookie=0x790ba3355d0c209b, duration=501.037s, table=7, n_packets=12, n_bytes=1259, idle_age=448, priority=100 actions=output:1
```

### Host Traffic

NOTE: Host-> svc (NP/EIP/LB) is neither "internal" nor "external" traffic, hence it defaults to special case "Cluster" even if ETP=local. Only Host->differentNP traffic flow obeys ETP=local.

## ExternalTrafficPolicy=Cluster

#### **Local Gateway Mode**

The implementation of this case differs for local gateway from that for shared gateway. In local gateway all service traffic is sent straight to host (instead of sending it to OVN) to allow users to apply custom routes according to their use cases.

In local gateway mode, rather than sending the traffic from breth0 into OVN via gateway router, we use flows on breth0 to send it into the host.

```text
          host (ovn-worker, 172.18.0.3) ---- 172.18.0.3 LOCAL(host) -- iptables -- breth0 -- GR -- 10.244.1.3 pod
           ^
           ^
           |
eth0--->|breth0|

```

1. Match on the incoming traffic via default flow on `table0`, send it to `table1`:

```
cookie=0xdeff105, duration=3189.786s, table=0, n_packets=99979, n_bytes=298029215, priority=50,ip,in_port=eth0 actions=ct(table=1,zone=64000)
```

2. Send it out to LOCAL ovs port on breth0 and traffic is delivered to the host:

```
cookie=0xdeff105, duration=3189.787s, table=1, n_packets=108, n_bytes=23004, priority=0 actions=NORMAL
```

3. In the host, we have an IPtable rule in the PREROUTING chain that DNATs this packet matched on nodePort to its clusterIP:targetPort

```
[8:480] -A OVN-KUBE-NODEPORT -p tcp -m addrtype --dst-type LOCAL -m tcp --dport 31842 -j DNAT --to-destination 10.96.67.170:80
```

4. The service route in the host sends this packet back to breth0.

```
10.96.0.0/16 via 172.18.0.1 dev breth0 mtu 1400
```

5. On breth0, we have priority 500 flows meant to handle hairpining, that will SNAT the srcIP to the special `169.254.169.2` masqueradeIP and send it to `table2`

```
cookie=0xdeff105, duration=3189.786s, table=0, n_packets=11, n_bytes=814, priority=500,ip,in_port=LOCAL,nw_dst=10.96.0.0/16 actions=ct(commit,table=2,zone=64001,nat(src=169.254.169.2))
```

6. In `table2` we have a flow that forwards this to patch port that takes the traffic in OVN:

```
cookie=0xdeff105, duration=6.308s, table=2, n_packets=11, n_bytes=814, actions=mod_dl_dst:02:42:ac:12:00:03,output:"patch-breth0_ov"
```

7. Traffic enters the GR on the worker node and hits the load-balancer where we DNAT it correctly to the local backends.

The GR load-balancer on a node with endpoints for the clusterIP will look like this:

```
_uuid               : b3201caf-3089-4462-b96e-1406fd7c4256
external_ids        : {"k8s.ovn.org/kind"=Service, "k8s.ovn.org/owner"="default/example-service-1"}
health_check        : []
ip_port_mappings    : {}
name                : "Service_default/example-service-1_TCP_cluster"
options             : {event="false", reject="true", skip_snat="false"}
protocol            : tcp
selection_fields    : []
vips                : {"10.96.67.170:80"="10.244.1.3:8080,10.244.2.3:8080"}
```

Response traffic will follow the same path (backend->GR->breth0->host->breth0->eth0).

7. Return traffic gets matched on the priority 500 flow in `table0` which sends it to `table3`.

```
cookie=0xdeff105, duration=3189.786s, table=0, n_packets=10, n_bytes=540, priority=500,ip,in_port="patch-breth0_ov",nw_src=10.96.0.0/16,nw_dst=169.254.169.2 actions=ct(table=3,zone=64001,nat)
```

8. In `table3`, we send it to host:

```
cookie=0xdeff105, duration=6.308s, table=3, n_packets=10, n_bytes=540, actions=move:NXM_OF_ETH_DST[]->NXM_OF_ETH_SRC[],mod_dl_dst:02:42:ac:12:00:03,LOCAL
```

9. From host we send it back to breth0 using:

```
cookie=0xdeff105, duration=5992.878s, table=0, n_packets=89312, n_bytes=6154654, idle_age=0, priority=100,ip,in_port=LOCAL actions=ct(commit,zone=64000,exec(load:0x2->NXM_NX_CT_MARK[])),output:eth0
```

where packet leaves the node and goes back to the external entity that initiated the connection.

## Sources
- https://www.asykim.com/blog/deep-dive-into-kubernetes-external-traffic-policies
