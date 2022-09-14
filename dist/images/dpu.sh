export K8S_APISERVER="https://192.168.1.100:6443"
export K8S_NODE="k8s-worker0"
export K8S_TOKEN="eyJhbGciOiJSUzI1NiIsImtpZCI6InJIYXJHWHVWX2hubTRZb2Ftb0lsU1hlRVNkcTh1aE5GR2pzYjRyWGEzd1kifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNjU5OTY0MzYyLCJpYXQiOjE2NTk5NjA3NjIsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJvdm4ta3ViZXJuZXRlcyIsInNlcnZpY2VhY2NvdW50Ijp7Im5hbWUiOiJvdm4iLCJ1aWQiOiI0Y2FjNTMwNi02MDdhLTQwMWItOWVhMi05YTJiZWZmOGJiM2YifX0sIm5iZiI6MTY1OTk2MDc2Miwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50Om92bi1rdWJlcm5ldGVzOm92biJ9.LBI5xQqveg-kgMw_r84Ncy-nRMkkgAKBpTkTfvYe3cFA-OPlQ_35sezu99VlpHXfnhdCXCYinVF8JfJtVDAPU2x2kn_st42SQQcwhAQC0eC0fRogmlYjPO_vBnfbDAilcNJ6TuYiWfkC1nVTND_drVX1TUsdywQztnEFFUj2-2O4SO3DBRS7yDOxBypvz0xfR6YmWC6yJt6KEgby5LjmJt5Lege2Tdd89KmuzdGVRzuSakXNEQAeYu0W5kbLS05Lv7BzE7QD57uVhkPJ6XdiRVguNPGs59ev_PIJgWfKNIDRlMAFBNx105WIi9mfU3mjxnQE1_diC87Vz0F2xyUqXg"
export K8S_CACERT="/home/core/ca.crt"
export OVN_NET_CIDR="172.16.0.0/16"
export OVN_SVC_CIDR="10.96.0.0/16"
export DPU_IP="10.5.210.16"
# for external traffic to go through a different gateway than the default,
# add to the below: --gateway-nexthop=<next-hop-ip>
export OVN_GATEWAY_OPTS='--gateway-interface=enp8s0'
export OVNKUBE_NODE_MGMT_PORT_NETDEV=enp9s0 # The representor  of the VF that used for --ovnkube-node-mgmt-port-netdev in deployment on host
export OVN_DISABLE_PKT_MTU_CHECK=true
 
# Assume still in dist/images
# Modify container image name in scripts below in case it
# differs than ovn-daemonset
./run-ovn-dpu.sh
./run-ovnkube-node-dpu.sh
