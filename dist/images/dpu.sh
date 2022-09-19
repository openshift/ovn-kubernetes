sudo chmod 666 /var/run/docker.sock
docker rm -vf $(docker ps -a -q)
export K8S_APISERVER="https://10.5.210.201:6443"
export K8S_NODE="k8s-worker-octeon"
export K8S_TOKEN=`ssh core@10.5.210.201 "kubectl create token ovn -n ovn-kubernetes"`
export K8S_CACERT="/home/dpu/ca.crt"
export OVN_NET_CIDR="172.16.0.0/16"
export OVN_SVC_CIDR="10.96.0.0/16"
export DPU_IP="10.5.210.21"
# for external traffic to go through a different gateway than the default,
# add to the below: --gateway-nexthop=<next-hop-ip>
#export OVN_GATEWAY_OPTS='--gateway-interface=enp1s0f1'
export OVNKUBE_NODE_MGMT_PORT_NETDEV=enP2p15s0v0 # The representor  of the VF that used for --ovnkube-node-mgmt-port-netdev in deployment on host
export OVN_DISABLE_PKT_MTU_CHECK=true
 
# Assume still in dist/images
# Modify container image name in scripts below in case it
# differs than ovn-daemonset
./run-ovn-dpu.sh
./run-ovnkube-node-dpu.sh
