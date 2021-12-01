# How to use Open Virtual Networking with Kubernetes

On Linux, the easiest way to get started is to use OVN DaemonSet and Deployments.

## Install Open vSwitch kernel modules on all hosts.

Most Linux distributions come with Open vSwitch kernel module by default.  You
can check its existence with `modinfo openvswitch`.  The features that OVN
needs are only available in kernel 4.6 and greater. But, you can also install
Open vSwitch kernel module from the Open vSwitch repository to get all the
features OVN needs (and any possible bug fixes) for any kernel.

To install Open vSwitch kernel module from Open vSwitch repo manually, please
read [INSTALL.rst](https://docs.openvswitch.org/en/latest/intro/install/). 

## Run DaemonSet and Deployment

Create OVN StatefulSet, DaemonSet and Deployment yamls from templates by running the commands below:
(The $MASTER_IP below is the IP address of the machine where kube-apiserver is
running).

```
# Clone ovn-kubernetes repo
mkdir -p $HOME/work/src/github.com/ovn-org
cd $HOME/work/src/github.com/ovn-org
git clone https://github.com/ovn-org/ovn-kubernetes
cd $HOME/work/src/github.com/ovn-org/ovn-kubernetes/dist/images
./daemonset.sh --image=docker.io/ovnkube/ovn-daemonset-u:latest \
    --net-cidr=192.168.0.0/16/24 --svc-cidr=172.16.1.0/24 \
    --gateway-mode="local" \
    --k8s-apiserver=https://$MASTER_IP:6443
```

To set specific logging level for OVN components, pass the related parameter from the below mentioned
list to the above command. Set values are the default values.
```
    --master-loglevel="5" \\Log level for ovnkube (master)
    --node-loglevel="5" \\ Log level for ovnkube (node)
    --dbchecker-loglevel="5" \\Log level for ovn-dbchecker (ovnkube-db)
    --ovn-loglevel-northd="-vconsole:info -vfile:info" \\ Log config for ovn northd
    --ovn-loglevel-nb="-vconsole:info -vfile:info" \\ Log config for northbound db
    --ovn-loglevel-sb="-vconsole:info -vfile:info" \\ Log config for southboudn db
    --ovn-loglevel-controller="-vconsole:info" \\ Log config for ovn-controller
    --ovn-loglevel-nbctld="-vconsole:info" \\ Log config for nbctl daemon
```

If you are not running OVS directly in the nodes, you must apply the OVS Daemonset yaml.
```
kubectl create -f $HOME/work/src/github.com/ovn-org/ovn-kubernetes/dist/yaml/ovs-node.yaml
```

Apply OVN DaemonSet and Deployment yamls.

```
# Create OVN namespace, service accounts, ovnkube-db headless service, configmap, and policies
kubectl create -f $HOME/work/src/github.com/ovn-org/ovn-kubernetes/dist/yaml/ovn-setup.yaml

# Optionally, if you plan to use the Egress IPs or EgressFirewall features, create the corresponding CRDs:
# create egressips.k8s.ovn.org CRD
kubectl create -f $HOME/work/src/github.com/ovn-org/ovn-kubernetes/dist/yaml/k8s.ovn.org_egressips.yaml
# create egressfirewalls.k8s.ovn.org CRD
kubectl create -f $HOME/work/src/github.com/ovn-org/ovn-kubernetes/dist/yaml/k8s.ovn.org_egressfirewalls.yaml

# Run ovnkube-db deployment.
kubectl create -f $HOME/work/src/github.com/ovn-org/ovn-kubernetes/dist/yaml/ovnkube-db.yaml

# Run ovnkube-master deployment.
kubectl create -f $HOME/work/src/github.com/ovn-org/ovn-kubernetes/dist/yaml/ovnkube-master.yaml

# Run ovnkube daemonset for nodes
kubectl create -f $HOME/work/src/github.com/ovn-org/ovn-kubernetes/dist/yaml/ovnkube-node.yaml
```

NOTE: You don't need kube-proxy for OVN to work. You can delete that from your
cluster.

# Docs overview
## General

[OVN overlay network on Openshift](./docs/INSTALL.OPENSHIFT.md) describes how an OVN overlay 
network is setup on Openshift 3.10 and later. It explains the various components and how they 
come together to establish the OVN overlay network. People that are interested in understatnding 
how the ovn cni plugin is installed will find this useful.

[CI Tests](./docs/ci.md) describes how OVN-Kubernetes runs E2E tests, how to update the set
of tests that run and how to run these tests locally.

[OVN kubernetes KIND Setup](./docs/kind.md). KIND (Kubernetes in Docker) deployment of OVN kubernetes
is a fast and easy means to quickly install and test kubernetes with OVN kubernetes CNI. The value
proposition is really for developers who want to reproduce an issue or test a fix in an environment
that can be brought up locally and within a few minutes.

[Debugging OVN](./docs/debugging.md)

The golang based [ovn kubernetes go-controller](./go-controller/README.md) is a reliable way to
deploy the OVN SDN using kubernetes clients and watchers based on golang. Contains `ovnkube` and
`ovn-k8s-cni-overlay` build and usage instructions.

## Installation/configuration
[Installing OVS and OVN on Ubuntu](./docs/INSTALL.UBUNTU.md) both from packages and source

[SSL](./docs/INSTALL.SSL.md) This document explains the way one could use SSL for connectivity 
between OVN components.

[ovn-northd SSL](./docs/OVN-NORTHD.SSL.md) If the ovn-northd instance is not running on the same 
node as OVN NB and OVN SB database, then you will need to follow this doc to secure the communication
between ovn-northd and NB/SB databases.

[Config variables](./docs/config.md) The config file contains common configuration options shared
between the various ovn-kubernetes programs (ovnkube, ovn-k8s-cni-overlay, etc). This doc describes 
how to override the default values for some config options.

[How to use Open Virtual Networking with Kubernetes (manual installation)](./README_MANUAL.md).

## Features
[Egress Firewall](./docs/egress-firewall.md) The EgressFirewall feature enables a cluster
administrator to limit the external hosts that a pod in a project can access. 
The EgressFirewall object rules apply to all pods that share the namespace with the egressfirewall object.

[Hybrid Overlay](./docs/hybrid-overlay.md) feature creates VXLAN tunnels to nodes in the cluster that
have been excluded from the ovn-kubernetes overlay using the no-hostsubnet-nodes config option.
These tunnels allow pods on ovn-kubernetes nodes to communicate directly with other pods on nodes
that do not run ovn-kubernetes.

[OVN multicast](./docs/multicast.md) enables data to be delivered to multiple IP addresses simultaneously.
For this to happen, the 'receivers' join a multicast group, and the sender(s) send data to it.

[NetworkPolicy](./docs/network-policy.md) features and examples. By default the network traffic from and
to K8s pods is not restricted in any way. Using NetworkPolicy is a way to enforce network isolation
of selected pods.

[OVS Hardware Offload](./docs/ovs_offload.md). The OVS software based solution is CPU intensive,
affecting system performance and preventing fully utilizing available bandwidth.
OVS 2.8 and above support new feature called OVS Hardware Offload which improves performance significantly.
This feature allows to offload the OVS data-plane to the NIC while maintaining OVS control-plane unmodified.

[OVN central database High-availability](./docs/ha.md) OVN architecture has two central databases that 
can be clustered. The databases are OVN_Northbound and OVN_Southbound. This document explains how to 
cluster them and start various daemons for the ovn-kubernetes integration.

## Other
[Unit test mocks](./docs/mocks-ut-faq.md)

[ovnkube-trace](./docs/ovnkube-trace.md) a tool to trace packet simulations between points in an 
ovn-kubernetes driven cluster.

# OVN Kubernetes Basics
A good resource to get started with understanding `ovn-kubernetes` is the following recording and slides, which run through the basic architecture and functionality of the system.
[slides](https://docs.google.com/presentation/d/1vlEjEqqVz02P4_oubt_FmMSHrvpS8ewmHWNuEl4lKDI/edit?usp=sharing)
[recording](https://drive.google.com/file/d/1FogbqRgT-yIA8UKfcAQNXNQrcq5Hz0z9/view?usp=sharing)
