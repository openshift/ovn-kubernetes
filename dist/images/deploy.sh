./daemonset.sh --image-pull-policy=Always --image=docker.io/navadiaev/ovn-daemonset-f:latest --net-cidr=172.16.0.0/16 --svc-cidr=10.96.0.0/12 --gateway-mode="shared" --ovnkube-node-mgmt-port-netdev=ens259f0 --k8s-apiserver=https://10.5.210.201:6443 --multicast-enabled --disable-snat-multiple-gws --disable-pkt-mtu-check=true

kubectl delete -f ../yaml/ovn-setup.yaml
kubectl delete -f ../yaml/ovnkube-db.yaml
kubectl delete -f ../yaml/ovnkube-master.yaml
kubectl delete -f ../yaml/ovnkube-node.yaml
kubectl delete -f ../yaml/ovnkube-node-dpu-host.yaml


kubectl delete namespace ovn-kubernetes

kubectl create -f ../yaml/ovn-setup.yaml
kubectl create -f ../yaml/ovnkube-db.yaml
kubectl create -f ../yaml/ovnkube-master.yaml
kubectl create -f ../yaml/ovnkube-node.yaml
kubectl create -f ../yaml/ovnkube-node-dpu-host.yaml