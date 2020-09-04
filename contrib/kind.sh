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

# Some environments (Fedora32,31 on desktop), have problems when the cluster
# is deleted directly with kind `kind delete cluster --name ovn`, it restarts the host.
# The root cause is unknown, this also can not be reproduced in Ubuntu 20.04 or
# with Fedora32 Cloud, but it does not happen if we clean first the ovn-kubernetes resources.
delete()
{
  kubectl --kubeconfig ${HOME}/admin.conf delete namespace ovn-kubernetes
  sleep 5
  kind delete cluster --name ${KIND_CLUSTER_NAME:-ovn}
}

usage()
{
    echo "usage: kind.sh [[[-cf|--config-file <file>] [-kt|keep-taint] [-ha|--ha-enabled]"
    echo "                 [-ho|--hybrid-enabled] [-ii|--install-ingress] [-n4|--no-ipv4]"
    echo "                 [-i6|--ipv6] [-wk|--num-workers <num>] [-ds|--disable-snat-multiple-gws]"
    echo "                 [-sw|--allow-system-writes] [-gm|--gateway-mode <mode>]] |"
    echo "                [-h]]"
    echo ""
    echo "-cf | --config-file               Name of the KIND J2 configuration file."
    echo "                                  DEFAULT: ./kind.yaml.j2"
    echo "-kt | --keep-taint                Do not remove taint components."
    echo "                                  DEFAULT: Remove taint components."
    echo "-ha | --ha-enabled                Enable high availability. DEFAULT: HA Disabled."
    echo "-ho | --hybrid-enabled            Enable hybrid overlay. DEFAULT: Disabled."
    echo "-ds | --disable-snat-multiple-gws Disable SNAT for multiple gws. DEFAULT: Disabled."
    echo "-ii | --install-ingress           Flag to install Ingress Components."
    echo "                                  DEFAULT: Don't install ingress components."
    echo "-n4 | --no-ipv4                   Disable IPv4. DEFAULT: IPv4 Enabled."
    echo "-i6 | --ipv6                      Enable IPv6. DEFAULT: IPv6 Disabled."
    echo "-wk | --num-workers               Number of worker nodes. DEFAULT: HA - 2 worker"
    echo "                                  nodes and no HA - 0 worker nodes."
    echo "-sw | --allow-system-writes       Allow script to update system. Intended to allow"
    echo "                                  github CI to be updated with IPv6 settings."
    echo "                                  DEFAULT: Don't allow."
    echo "-gm | --gateway-mode              Enable 'shared' or 'local' gateway mode."
    echo "                                  DEFAULT: local."
    echo "-ov | --ovn-image            	    Use the specified docker image instead of building locally. DEFAULT: local build."
    echo "--delete                     	    Delete current cluster"
    echo ""
}

parse_args()
{
    while [ "$1" != "" ]; do
        case $1 in
            -cf | --config-file )               shift
                                                if test ! -f "$1"; then
                                                    echo "$1 does not  exist"
                                                    usage
                                                    exit 1
                                                fi
                                                KIND_CONFIG=$1
                                                ;;
            -ii | --install-ingress )           KIND_INSTALL_INGRESS=true
                                                ;;
            -ha | --ha-enabled )                KIND_HA=true
                                                ;;
            -me | --multicast-enabled)          OVN_MULTICAST_ENABLE=true
                                                ;;
            -ho | --hybrid-enabled )            OVN_HYBRID_OVERLAY_ENABLE=true
                                                ;;
            -ds | --disable-snat-multiple-gws ) OVN_DISABLE_SNAT_MULTIPLE_GWS=true
                                                ;;
            -kt | --keep-taint )                KIND_REMOVE_TAINT=false
                                                ;;
            -n4 | --no-ipv4 )                   KIND_IPV4_SUPPORT=false
                                                ;;
            -i6 | --ipv6 )                      KIND_IPV6_SUPPORT=true
                                                ;;
            -wk | --num-workers )               shift
                                                if ! [[ "$1" =~ ^[0-9]+$ ]]; then
                                                    echo "Invalid num-workers: $1"
                                                    usage
                                                    exit 1
                                                fi
                                                KIND_NUM_WORKER=$1
                                                ;;
            -sw | --allow-system-writes )       KIND_ALLOW_SYSTEM_WRITES=true
                                                ;;
            -gm | --gateway-mode )              shift
                                                if [ "$1" != "local" ] && [ "$1" != "shared" ]; then
                                                    echo "Invalid gateway mode: $1"
                                                    usage
                                                    exit 1
                                                fi
                                                OVN_GATEWAY_MODE=$1
                                                ;;
            -ov | --ovn-image )           	shift
                                          	OVN_IMAGE=$1
                                          	;;
            --delete )                    	delete
                                          	exit
                                          	;;
            -h | --help )                       usage
                                                exit
                                                ;;
            * )                                 usage
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
     echo "KIND_CONFIG_FILE = $KIND_CONFIG"
     echo "KIND_REMOVE_TAINT = $KIND_REMOVE_TAINT"
     echo "KIND_IPV4_SUPPORT = $KIND_IPV4_SUPPORT"
     echo "KIND_IPV6_SUPPORT = $KIND_IPV6_SUPPORT"
     echo "KIND_NUM_WORKER = $KIND_NUM_WORKER"
     echo "KIND_ALLOW_SYSTEM_WRITES = $KIND_ALLOW_SYSTEM_WRITES"
     echo "OVN_GATEWAY_MODE = $OVN_GATEWAY_MODE"
     echo "OVN_HYBRID_OVERLAY_ENABLE = $OVN_HYBRID_OVERLAY_ENABLE"
     echo "OVN_DISABLE_SNAT_MULTIPLE_GWS = $OVN_DISABLE_SNAT_MULTIPLE_GWS"
     echo "OVN_MULTICAST_ENABLE = $OVN_MULTICAST_ENABLE"
     echo "OVN_IMAGE = $OVN_IMAGE"
     echo ""
}

parse_args $*

# ensure j2 renderer installed
pip install wheel
pip freeze | grep j2cli || pip install j2cli[yaml] --user
export PATH=~/.local/bin:$PATH

# Set default values
KIND_CLUSTER_NAME=${KIND_CLUSTER_NAME:-ovn}
K8S_VERSION=${K8S_VERSION:-v1.18.2}
OVN_GATEWAY_MODE=${OVN_GATEWAY_MODE:-local}
KIND_INSTALL_INGRESS=${KIND_INSTALL_INGRESS:-false}
KIND_HA=${KIND_HA:-false}
KIND_CONFIG=${KIND_CONFIG:-./kind.yaml.j2}
KIND_REMOVE_TAINT=${KIND_REMOVE_TAINT:-true}
KIND_IPV4_SUPPORT=${KIND_IPV4_SUPPORT:-true}
KIND_IPV6_SUPPORT=${KIND_IPV6_SUPPORT:-false}
OVN_HYBRID_OVERLAY_ENABLE=${OVN_HYBRID_OVERLAY_ENABLE:-false}
OVN_DISABLE_SNAT_MULTIPLE_GWS=${OVN_DISABLE_SNAT_MULTIPLE_GWS:-false}
OVN_MULTICAST_ENABLE=${OVN_MULTICAST_ENABLE:-false}
KIND_ALLOW_SYSTEM_WRITES=${KIND_ALLOW_SYSTEM_WRITES:-false}
OVN_IMAGE=${OVN_IMAGE:-local}

# Input not currently validated. Modify outside script at your own risk.
# These are the same values defaulted to in KIND code (kind/default.go).
# NOTE: KIND NET_CIDR_IPV6 default use a /64 but OVN have a /64 per host
# so it needs to use a larger subnet
#  Upstream - NET_CIDR_IPV6=fd00:10:244::/64 SVC_CIDR_IPV6=fd00:10:96::/112
NET_CIDR_IPV4=${NET_CIDR_IPV4:-10.244.0.0/16}
SVC_CIDR_IPV4=${SVC_CIDR_IPV4:-10.96.0.0/16}
NET_CIDR_IPV6=${NET_CIDR_IPV6:-fd00:10:244::/48}
SVC_CIDR_IPV6=${SVC_CIDR_IPV6:-fd00:10:96::/112}

KIND_NUM_MASTER=1
if [ "$KIND_HA" == true ]; then
  KIND_NUM_MASTER=3
  KIND_NUM_WORKER=${KIND_NUM_WORKER:-0}
else
  KIND_NUM_WORKER=${KIND_NUM_WORKER:-2}
fi

print_params

set -euxo pipefail

# Detect IP to use as API server
#
# You can't use an IPv6 address for the external API, docker does not support
# IPv6 port mapping. Always use the IPv4 host address for the API Server field.
# This will keep compatibility and people will be able to connect with kubectl
# from outside
#
# ip -4 addr -> Run ip command for IPv4
# grep -oP '(?<=inet\s)\d+(\.\d+){3}' -> Use only the lines with the
#   IPv4 Addresses and strip off the trailing subnet mask, /xx
# grep -v "127.0.0.1" -> Remove local host
# head -n 1 -> Of the remaining, use first entry
API_IP=$(ip -4 addr | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v "127.0.0.1" | head -n 1)
if [ -z "$API_IP" ]; then
  echo "Error detecting machine IPv4 to use as API server. Default to 0.0.0.0."
  API_IP=0.0.0.0
fi

check_ipv6() {
  # Collect additional IPv6 data on test environment
  ERROR_FOUND=false
  TMPVAR=`sysctl net.ipv6.conf.all.forwarding | awk '{print $3}'`
  echo "net.ipv6.conf.all.forwarding is equal to $TMPVAR"
  if [ "$TMPVAR" != 1 ]; then
    if [ "$KIND_ALLOW_SYSTEM_WRITES" == true ]; then
      sudo sysctl -w net.ipv6.conf.all.forwarding=1
    else
      echo "RUN: 'sudo sysctl -w net.ipv6.conf.all.forwarding=1' to use IPv6."
      ERROR_FOUND=true
    fi
  fi
  TMPVAR=`sysctl net.ipv6.conf.all.disable_ipv6 | awk '{print $3}'`
  echo "net.ipv6.conf.all.disable_ipv6 is equal to $TMPVAR"
  if [ "$TMPVAR" != 0 ]; then
    if [ "$KIND_ALLOW_SYSTEM_WRITES" == true ]; then
      sudo sysctl -w net.ipv6.conf.all.disable_ipv6=0
    else
      echo "RUN: 'sudo sysctl -w net.ipv6.conf.all.disable_ipv6=0' to use IPv6."
      ERROR_FOUND=true
    fi
  fi
  if [ -f /proc/net/if_inet6 ]; then
    echo "/proc/net/if_inet6 exists so IPv6 supported in kernel."
  else
    echo "/proc/net/if_inet6 does not exists so no IPv6 support found! Compile the kernel!!"
    ERROR_FOUND=true
  fi
  if "$ERROR_FOUND"; then
    exit 2
  fi
}

if [ "$KIND_IPV6_SUPPORT" == true ]; then
  check_ipv6
fi

if [ "$KIND_IPV4_SUPPORT" == true ] && [ "$KIND_IPV6_SUPPORT" == false ]; then
  IP_FAMILY=""
  NET_CIDR=$NET_CIDR_IPV4
  SVC_CIDR=$SVC_CIDR_IPV4
  echo "IPv4 Only Support: API_IP=$API_IP --net-cidr=$NET_CIDR --svc-cidr=$SVC_CIDR"
elif [ "$KIND_IPV4_SUPPORT" == false ] && [ "$KIND_IPV6_SUPPORT" == true ]; then
  IP_FAMILY="ipv6"
  NET_CIDR=$NET_CIDR_IPV6
  SVC_CIDR=$SVC_CIDR_IPV6
  echo "IPv6 Only Support: API_IP=$API_IP --net-cidr=$NET_CIDR --svc-cidr=$SVC_CIDR"
elif [ "$KIND_IPV4_SUPPORT" == true ] && [ "$KIND_IPV6_SUPPORT" == true ]; then
  IP_FAMILY="DualStack"
  NET_CIDR=$NET_CIDR_IPV4,$NET_CIDR_IPV6
  SVC_CIDR=$SVC_CIDR_IPV4,$SVC_CIDR_IPV6
  echo "Dual Stack Support: API_IP=$API_IP --net-cidr=$NET_CIDR --svc-cidr=$SVC_CIDR"
else
  echo "Invalid setup. KIND_IPV4_SUPPORT and/or KIND_IPV6_SUPPORT must be true."
  exit 1
fi

# Output of the j2 command
KIND_CONFIG_LCL=./kind.yaml

ovn_apiServerAddress=${API_IP} \
  ovn_ip_family=${IP_FAMILY} \
  ovn_ha=${KIND_HA} \
  net_cidr=${NET_CIDR} \
  svc_cidr=${SVC_CIDR} \
  ovn_num_master=${KIND_NUM_MASTER} \
  ovn_num_worker=${KIND_NUM_WORKER} \
  cluster_log_level=${KIND_CLUSTER_LOGLEVEL:-4} \
  j2 ${KIND_CONFIG} -o ${KIND_CONFIG_LCL}

# Create KIND cluster. For additional debug, add '--verbosity <int>': 0 None .. 3 Debug
export KUBECONFIG=${HOME}/admin.conf
kind create cluster --name ${KIND_CLUSTER_NAME} --kubeconfig ${KUBECONFIG} --image kindest/node:${K8S_VERSION} --config=${KIND_CONFIG_LCL}
cat ${KUBECONFIG}

if [ "${GITHUB_ACTIONS:-false}" == "true" ]; then
  # Patch CoreDNS to work in Github CI
  # 1. Github CI doesn´t offer IPv6 connectivity, so CoreDNS should be configured
  # to work in an offline environment:
  # https://github.com/coredns/coredns/issues/2494#issuecomment-457215452
  # 2. Github CI adds following domains to resolv.conf search field:
  # .net.
  # CoreDNS should handle those domains and answer with NXDOMAIN instead of SERVFAIL
  # otherwise pods stops trying to resolve the domain.
  # Get the current config
  original_coredns=$(kubectl get -oyaml -n=kube-system configmap/coredns)
  echo "Original CoreDNS config:"
  echo "${original_coredns}"
  # Patch it
  fixed_coredns=$(
    printf '%s' "${original_coredns}" | sed \
      -e 's/^.*kubernetes cluster\.local/& net/' \
      -e '/^.*upstream$/d' \
      -e '/^.*fallthrough.*$/d' \
      -e '/^.*forward . \/etc\/resolv.conf$/d' \
      -e '/^.*loop$/d' \
  )
  echo "Patched CoreDNS config:"
  echo "${fixed_coredns}"
  printf '%s' "${fixed_coredns}" | kubectl apply -f -
fi

if [ "$OVN_IMAGE" == local ]; then
  # Build ovn docker image
  pushd ../go-controller
  make
  popd

  # Build ovn kube image
  pushd ../dist/images
  sudo cp -f ../../go-controller/_output/go/bin/* .
  echo "ref: $(git rev-parse  --symbolic-full-name HEAD)  commit: $(git rev-parse  HEAD)" > git_info
  docker build -t ovn-daemonset-f:dev -f Dockerfile.fedora .
  OVN_IMAGE=ovn-daemonset-f:dev
  popd
fi

# Detect API IP address for OVN

# Despite OVN run in pod they will only obtain the VIRTUAL apiserver address
# and since OVN has to provide the connectivity to service
# it can not be bootstrapped

# This is the address of the node with the control-plane
API_URL=$(kind get kubeconfig --internal --name ${KIND_CLUSTER_NAME} | grep server | awk '{ print $2 }')

# Create ovn-kube manifests
pushd ../dist/images
./daemonset.sh \
  --image=${OVN_IMAGE} \
  --net-cidr=${NET_CIDR} \
  --svc-cidr=${SVC_CIDR} \
  --gateway-mode=${OVN_GATEWAY_MODE} \
  --hybrid-enabled=${OVN_HYBRID_OVERLAY_ENABLE} \
  --disable-snat-multiple-gws=${OVN_DISABLE_SNAT_MULTIPLE_GWS} \
  --multicast-enabled=${OVN_MULTICAST_ENABLE} \
  --k8s-apiserver=${API_URL} \
  --ovn-master-count=${KIND_NUM_MASTER} \
  --kind \
  --ovn-unprivileged-mode=no \
  --master-loglevel=5 \
  --egress-ip-enable=true
popd

kind load docker-image ${OVN_IMAGE} --name ${KIND_CLUSTER_NAME}

pushd ../dist/yaml
run_kubectl apply -f k8s.ovn.org_egressfirewalls.yaml
run_kubectl apply -f k8s.ovn.org_egressips.yaml
run_kubectl apply -f ovn-setup.yaml
CONTROL_NODES=$(docker ps -f name=ovn-control | grep -v NAMES | awk '{ print $NF }')
for n in $CONTROL_NODES; do
  run_kubectl label node $n k8s.ovn.org/ovnkube-db=true
  if [ "$KIND_REMOVE_TAINT" == true ]; then
    run_kubectl taint node $n node-role.kubernetes.io/master:NoSchedule-
  fi
done
if [ "$KIND_HA" == true ]; then
  run_kubectl apply -f ovnkube-db-raft.yaml
else
  run_kubectl apply -f ovnkube-db.yaml
fi
run_kubectl apply -f ovnkube-master.yaml
run_kubectl apply -f ovnkube-node.yaml
popd

# Delete kube-proxy
run_kubectl -n kube-system delete ds kube-proxy
kind get clusters
kind get nodes --name ${KIND_CLUSTER_NAME}
kind export kubeconfig --name ${KIND_CLUSTER_NAME}
if [ "$KIND_INSTALL_INGRESS" == true ]; then
  run_kubectl apply -f ingress/mandatory.yaml
  run_kubectl apply -f ingress/service-nodeport.yaml
fi

# Check that everything is fine and running. IPv6 cluster seems to take a little
# longer to come up, so extend the wait time.
OVN_TIMEOUT=300s
if [ "$KIND_IPV6_SUPPORT" == true ]; then
  OVN_TIMEOUT=480s
fi
if ! kubectl wait -n ovn-kubernetes --for=condition=ready pods --all --timeout=${OVN_TIMEOUT} ; then
  echo "some pods in OVN Kubernetes are not running"
  kubectl get pods -A -o wide || true
  exit 1
fi
if ! kubectl wait -n kube-system --for=condition=ready pods --all --timeout=300s ; then
  echo "some pods in the system are not running"
  kubectl get pods -A -o wide || true
  exit 1
fi

echo "Pods are all up, allowing things settle for 30 seconds..."
sleep 30
