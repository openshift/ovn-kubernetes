#!/bin/bash
set -o nounset
set -o errexit
set -o pipefail

echo "************ BGP Setup Cleanup ************"

SUDO=
if [ "$EUID" -ne 0 ]; then
  SUDO="sudo"
fi

CLI="$SUDO podman"
if ! command -v "podman" &>/dev/null; then
    CLI="$SUDO docker"
fi
echo "Container CLI is: $CLI"

KCLI="kubectl"
if ! command -v $KCLI &>/dev/null; then
    KCLI="oc"
fi

IP="$SUDO ip"
IPTABLES="$SUDO iptables"
IP6TABLES="$SUDO ip6tables"

# Network CIDRs (should match setup script)
CLUSTER_NETWORK_V4="10.128.0.0/14"
CLUSTER_NETWORK_V6="fd01::/48"

echo "Removing iptables rules and routes..."

# Remove IPv4 iptables rules
$IPTABLES -t nat -D POSTROUTING -s ${CLUSTER_NETWORK_V4} ! -d 192.168.111.1/24 -j MASQUERADE 2>/dev/null || true
$IPTABLES -t filter -D FORWARD -d ${CLUSTER_NETWORK_V4} -o ostestbm -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
$IPTABLES -t filter -D FORWARD -s ${CLUSTER_NETWORK_V4} -i ostestbm -j ACCEPT 2>/dev/null || true

# Remove IPv4 route
$IP route del $CLUSTER_NETWORK_V4 via 192.168.111.3 dev ostestbm 2>/dev/null || true

# Remove IPv6 iptables rules
$IP6TABLES -t nat -D POSTROUTING -s ${CLUSTER_NETWORK_V6} ! -d fd2e:6f44:5dd8:c956::1 -j MASQUERADE 2>/dev/null || true
$IP6TABLES -t filter -D FORWARD -d ${CLUSTER_NETWORK_V6} -o ostestbm -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
$IP6TABLES -t filter -D FORWARD -s ${CLUSTER_NETWORK_V6} -i ostestbm -j ACCEPT 2>/dev/null || true

# Remove IPv6 route
$IP -6 route del $CLUSTER_NETWORK_V6 via fd2e:6f44:5dd8:c956::3 dev ostestbm 2>/dev/null || true

echo "Removing Kubernetes resources..."

# Get list of networks that have RouteAdvertisements (to clean up FRRConfiguration later)
NETWORKS=($($KCLI get routeadvertisements -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || echo ""))

# Remove RouteAdvertisements
for network in "${NETWORKS[@]}"; do
    if [ -n "$network" ]; then
        echo "Removing RouteAdvertisement: $network"
        $KCLI delete routeadvertisements "$network" --ignore-not-found=true
    fi
done

# Remove FRRConfigurations
for network in "${NETWORKS[@]}"; do
    if [ -n "$network" ]; then
        if [ "$network" = "default" ]; then
            echo "Removing FRRConfiguration: receive-filtered"
            $KCLI delete frrconfiguration -n openshift-frr-k8s receive-filtered --ignore-not-found=true
        else
            echo "Removing FRRConfiguration: receive-filtered-$network"
            $KCLI delete frrconfiguration -n openshift-frr-k8s receive-filtered-$network --ignore-not-found=true
        fi
    fi
done

echo "Removing containers..."

# Get extra network name if it exists
EXTRA_NETWORK=$(echo ${EXTRA_NETWORK_NAMES:-} | awk '{print $1;}')

# Stop and remove agnhost containers
$CLI rm -f agnhost 2>/dev/null || true
if [ -n "$EXTRA_NETWORK" ]; then
    $CLI rm -f agnhost_$EXTRA_NETWORK 2>/dev/null || true
fi

# Stop and remove FRR container
$CLI rm -f frr 2>/dev/null || true

echo "Removing container networks..."

# Remove container networks
$CLI network rm -f agnhost_net 2>/dev/null || true
$CLI network rm -f ostestbm_net 2>/dev/null || true

if [ -n "$EXTRA_NETWORK" ]; then
    $CLI network rm -f ${EXTRA_NETWORK}_net 2>/dev/null || true
    $CLI network rm -f agnhost_${EXTRA_NETWORK}_net 2>/dev/null || true
fi

echo "Removing dummy network interfaces..."

# Remove dummy interfaces (we created DUMMY=0, and potentially DUMMY=1 for extra network)
for i in {0..10}; do
    $IP link del dummy$i 2>/dev/null || true
done

echo "Cleanup completed successfully!"

echo ""
echo "Summary of cleaned up resources:"
echo "  - FRR container and network"
echo "  - Agnhost containers and networks"
echo "  - Dummy network interfaces"
echo "  - Kubernetes FRRConfiguration and RouteAdvertisements"
echo "  - IP routes and iptables rules"
echo ""
echo "Note: ipForwarding setting was NOT reverted (see commented section in script)"