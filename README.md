# How to use Open Virtual Networking with Kubernetes

DO NOT MERGE: Adding debug to OVN so collecting prow job.

On Linux, the easiest way to get started is to use OVN daemonset and deployments.

## Install Open vSwitch kernel modules on all hosts.

Most Linux distributions come with openvswitch kernel module by default.  You
can check its existence with `modinfo openvswitch`.  The features that OVN
needs are only available in kernel 4.6 and greater. But, you can also install
openvswitch kernel module from the openvswitch repository to get all the
features OVN needs (and any possible bug fixes) for any kernel.

To install openvswitch kernel module from openvswitch repo manually, please
read [INSTALL.rst].  For a quick start on Ubuntu,  you can install
the kernel module package by:

```
sudo apt-get install apt-transport-https
echo "deb http://3.19.28.122/openvswitch/stable /" |  sudo tee /etc/apt/sources.list.d/openvswitch.list
wget -O - http://3.19.28.122/openvswitch/keyFile |  sudo apt-key add -
sudo apt-get update
sudo apt-get build-dep dkms
sudo apt-get install openvswitch-datapath-dkms -y
```

## Run daemonset and deployments

On Kubernetes master, label it to run daemonsets.

```
kubectl taint nodes --all node-role.kubernetes.io/master-
```

Create OVN daemonset and deployment yamls from templates by running the commands below:
(The $MASTER_IP below is the IP address of the machine where kube-apiserver is
running). Note, when specifying the pod CIDR to the command below, daemonset.sh will
generate a /24 subnet prefix to create per-node CIDRs. Ensure your pod subnet is has a
prefix less than 24, or edit hte  generated ovn-setup.yaml and specify a host subnet
prefix. For example, providing a net-cidr of "129.168.1.0/24" would require modifying
ovn-setup.yaml with a host subnet prefix as follows:

```
data:
  net_cidr:      "192.168.1.0/24/25"
```

Where "/25" is just chosen for this example, but may be any legitimate prefix value greater
than 24.

```
# Clone ovn-kubernetes repo
mkdir -p $HOME/work/src/github.com/ovn-org
cd $HOME/work/src/github.com/ovn-org
git clone https://github.com/ovn-org/ovn-kubernetes
cd $HOME/work/src/github.com/ovn-org/ovn-kubernetes/dist/images
./daemonset.sh --image=docker.io/ovnkube/ovn-daemonset-u:latest \
    --net-cidr=192.168.0.0/16 --svc-cidr=172.16.1.0/24 \
    --gateway-mode="local" \
    --k8s-apiserver=https://$MASTER_IP:6443
```

Apply OVN daemonset and deployment yamls.

```
# Create OVN namespace, service accounts, ovnkube-db headless service, configmap, and policies
kubectl create -f $HOME/work/src/github.com/ovn-org/ovn-kubernetes/dist/yaml/ovn-setup.yaml

# Run ovnkube-db deployment.
kubectl create -f $HOME/work/src/github.com/ovn-org/ovn-kubernetes/dist/yaml/ovnkube-db.yaml

# Run ovnkube-master deployment.
kubectl create -f $HOME/work/src/github.com/ovn-org/ovn-kubernetes/dist/yaml/ovnkube-master.yaml

# Run ovnkube daemonset for nodes
kubectl create -f $HOME/work/src/github.com/ovn-org/ovn-kubernetes/dist/yaml/ovnkube-node.yaml
```

NOTE: You don't need kube-proxy for OVN to work. You can delete that from your
cluster.

## Manual installation and Vagrant

For Windows, (and to understand what daemonsets run internally), please read
[MANUAL.md].  For more advanced use cases too (like SSL, HA of databases, and various
gateway modes supported), please read [MANUAL.md].

[INSTALL.rst]: http://docs.openvswitch.org/en/latest/intro/install
[MANUAL.md]: README_MANUAL.md
