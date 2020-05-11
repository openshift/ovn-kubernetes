#!/usr/bin/env bash

run_kubectl() {
  local retries=0
  local attempts=10
  while true; do
    if kubectl "$@"; then
      break
    fi

    ((retries += 1))
    if [[ "${retries}" -gt ${attempts} ]]; then
      echo "error: 'kubectl $*' did not succeed, failing"
      exit 1
    fi
    echo "info: waiting for 'kubectl $*' to succeed..."
    sleep 1
  done
}

usage()
{
    echo "usage: kind.sh [[[-cf|--config-file file ] [-ii|--install-ingress] [-ha|--ha-enabled] [-kt|keep-taint]] | [-h]]"
    echo ""
    echo "-cf | --config-file          Name of the KIND configuration file if default files are not sufficient"
    echo "-ii | --install-ingress      Flag to install Ingress Components"
    echo "-ha | --ha-enabled           If high availability needs to be enabled by default"
    echo "-kt | --keep-taint           Do not remove taint components"
    echo ""
} 

parse_args()
{   
    while [ "$1" != "" ]; do
        case $1 in
            -cf | --config-file )      shift
                                       if test ! -f "$1"; then
                                          echo "$1 does not  exist"
                                          usage
                                          exit 1
                                       fi
                                       KIND_CONFIG=$1
                                       ;;
            -ii | --install-ingress )  KIND_INSTALL_INGRESS=true
                                       ;;
            -ha | --ha-enabled )       KIND_HA=true
                                       ;;
            -kt | --keep-taint )       KIND_REMOVE_TAINT=false
                                       ;;
            -h | --help )              usage
                                       exit
                                       ;;
            * )                        usage
                                       exit 1
        esac
        shift
    done
}

print_params()
{ 
     echo "Using these parameters to install KIND"
     echo ""
     echo "KIND_INSTALL_INGRESS = $KIND_INSTALL_INGRESS"
     echo "KIND_HA = $KIND_HA"
     echo "KIND_CONFIG_FILE = $KIND_CONFIG "
     echo "KIND_REMOVE_TAINT = $KIND_REMOVE_TAINT"
     echo ""
}

parse_args $*

MASTER_COUNT=1
K8S_VERSION=${K8S_VERSION:-v1.17.2}
KIND_INSTALL_INGRESS=${KIND_INSTALL_INGRESS:-false}
KIND_HA=${KIND_HA:-false}
if [ "$KIND_HA" == true ]; then
  DEFAULT_KIND_CONFIG=./kind-ha.yaml
  MASTER_COUNT=`grep -c "^\s-\srole\s*:\s*control-plane" kind-ha.yaml`
else
  DEFAULT_KIND_CONFIG=./kind.yaml
  MASTER_COUNT=`grep -c "^\s-\srole\s*:\s*control-plane" kind.yaml`
fi
KIND_CONFIG=${KIND_CONFIG:-$DEFAULT_KIND_CONFIG}
KIND_REMOVE_TAINT=${KIND_REMOVE_TAINT:-true}

print_params

set -euxo pipefail

# Detect IP to use as API server
API_IP=$(ip -4 addr | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v "127.0.0.1" | head -n 1)
if [ -z "$API_IP" ]; then
  echo "Error detecting machine IP to use as API server"
  exit 1
fi

sed -i "s/apiServerAddress.*/apiServerAddress: ${API_IP}/" ${KIND_CONFIG}

# Create KIND cluster
KIND_CLUSTER_NAME=${KIND_CLUSTER_NAME:-ovn}
kind create cluster --name ${KIND_CLUSTER_NAME} --kubeconfig ${HOME}/admin.conf --image kindest/node:${K8S_VERSION} --config=${KIND_CONFIG}
export KUBECONFIG=${HOME}/admin.conf
cat ${KUBECONFIG}
mkdir -p /tmp/kind
sudo chmod 777 /tmp/kind
count=0
until kubectl get secrets -o jsonpath='{.items[].data.ca\.crt}'
do
  if [ $count -gt 10 ]; then
    echo "Failed to get k8s crt/token"
    exit 1
  fi
  count=$((count+1))
  echo "secrets not available on attempt $count"
  sleep 5
done
kubectl get secrets -o jsonpath='{.items[].data.ca\.crt}' > /tmp/kind/ca.crt
kubectl get secrets -o jsonpath='{.items[].data.token}' > /tmp/kind/token
pushd ../go-controller
make
popd
pushd ../dist/images
sudo cp -f ../../go-controller/_output/go/bin/* .
echo "ref: $(git rev-parse  --symbolic-full-name HEAD)  commit: $(git rev-parse  HEAD)" > git_info
docker build -t ovn-daemonset-f:dev -f Dockerfile.fedora .
./daemonset.sh --image=docker.io/library/ovn-daemonset-f:dev --net-cidr=10.244.0.0/16 --svc-cidr=10.96.0.0/12 --gateway-mode="local" --k8s-apiserver=https://${API_IP}:11337 --ovn-master-count=${MASTER_COUNT} --kind --master-loglevel=5
popd
kind load docker-image ovn-daemonset-f:dev --name ${KIND_CLUSTER_NAME}
pushd ../dist/yaml
run_kubectl create -f ovn-setup.yaml
CONTROL_NODES=$(docker ps -f name=ovn-control | grep -v NAMES | awk '{ print $NF }')
for n in $CONTROL_NODES; do
  run_kubectl label node $n k8s.ovn.org/ovnkube-db=true
  if [ "$KIND_REMOVE_TAINT" == true ]; then
    run_kubectl taint node $n node-role.kubernetes.io/master:NoSchedule-
  fi
done
if [ "$KIND_HA" == true ]; then
  run_kubectl create -f ovnkube-db-raft.yaml
else
  run_kubectl create -f ovnkube-db.yaml
fi
run_kubectl create -f ovnkube-master.yaml
run_kubectl create -f ovnkube-node.yaml
popd
run_kubectl -n kube-system delete ds kube-proxy
kind get clusters
kind get nodes --name ${KIND_CLUSTER_NAME}
kind export kubeconfig --name ovn
if [ "$KIND_INSTALL_INGRESS" == true ]; then
  run_kubectl apply -f ingress/mandatory.yaml
  run_kubectl apply -f ingress/service-nodeport.yaml
fi

count=1
until [ -z "$(kubectl get pod -A -o custom-columns=NAME:metadata.name,STATUS:.status.phase | tail -n +2 | grep -v Running)" ];do
  if [ $count -gt 15 ]; then
    echo "Some pods are not running after timeout"
    exit 1
  fi
  echo "All pods not available yet on attempt $count:"
  kubectl get pod -A || true
  count=$((count+1))
  sleep 10
done
echo "Pods are all up, allowing things settle for 30 seconds..."
sleep 30

