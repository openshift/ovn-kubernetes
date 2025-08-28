#!/usr/bin/env bash

set -ex

# setting this env prevents ginkgo e2e from trying to run provider setup
export KUBERNETES_CONFORMANCE_TEST=y
export KUBECONFIG=${KUBECONFIG:-${HOME}/ovn.conf}

# Skip tests which are not IPv6 ready yet (see description of https://github.com/ovn-org/ovn-kubernetes/pull/2276)
# (Note that netflow v5 is IPv4 only)
# NOTE: Some of these tests that check connectivity to internet cannot be run.
#       See https://github.com/actions/runner-images/issues/668#issuecomment-1480921915 for details
# There were some past efforts to re-enable some of these skipped tests, but that never happened and they are
# still failing v6 lane: https://github.com/ovn-org/ovn-kubernetes/pull/2505,
# https://github.com/ovn-org/ovn-kubernetes/pull/2524, https://github.com/ovn-org/ovn-kubernetes/pull/2287; so
# going to skip them again.
# TODO: Fix metalLB integration with KIND on IPV6 in LGW mode and enable those service tests.See
# https://github.com/ovn-org/ovn-kubernetes/issues/4131 for details.
# TODO: Fix EIP tests. See https://github.com/ovn-org/ovn-kubernetes/issues/4130 for details.
# TODO: Fix MTU tests. See https://github.com/ovn-org/ovn-kubernetes/issues/4160 for details.
IPV6_SKIPPED_TESTS="Should be allowed by externalip services|\
should provide connection to external host by DNS name from a pod|\
should provide Internet connection continuously when ovnkube-node pod is killed|\
should provide Internet connection continuously when pod running master instance of ovnkube-control-plane is killed|\
should provide Internet connection continuously when all pods are killed on node running master instance of ovnkube-control-plane|\
should provide Internet connection continuously when all ovnkube-control-plane pods are killed|\
Should validate flow data of br-int is sent to an external gateway with netflow v5|\
should be able to receive multicast IGMP query|\
test node readiness according to its defaults interface MTU size|\
Pod to pod TCP with low MTU|\
queries to the hostNetworked server pod on another node shall work for TCP|\
queries to the hostNetworked server pod on another node shall work for UDP|\
ipv4 pod"

SKIPPED_TESTS=""
skip() {
  if [ "$SKIPPED_TESTS" != "" ]; then
  	SKIPPED_TESTS+="|"
  fi
  SKIPPED_TESTS+=$*
}

if [ "$PLATFORM_IPV4_SUPPORT" == true ]; then
  if  [ "$PLATFORM_IPV6_SUPPORT" == true ]; then
	  # No support for these features in dual-stack yet
	   skip "hybrid.overlay"
  else
	  # Skip sflow in IPv4 since it's a long test (~5 minutes)
	  # We're validating netflow v5 with an ipv4 cluster, sflow with an ipv6 cluster
	  skip "Should validate flow data of br-int is sent to an external gateway with sflow|ipv6 pod"
  fi
fi

if [ "$PLATFORM_IPV4_SUPPORT" == false ]; then
  skip "\[IPv4\]"
fi

if [ "$OVN_HA" == false ]; then
  # No support for these features in no-ha mode yet
  # TODO streamline the db delete tests
  skip "recovering from deleting db files while maintaining connectivity"
  skip "Should validate connectivity before and after deleting all the db-pods at once in HA mode"
else 
  skip "Should validate connectivity before and after deleting all the db-pods at once in Non-HA mode"
  skip "e2e br-int NetFlow export validation"
fi

if [ "$PLATFORM_IPV6_SUPPORT" == true ]; then
  # No support for these tests in IPv6 mode yet
  skip $IPV6_SKIPPED_TESTS
fi

if [ "$OVN_DISABLE_SNAT_MULTIPLE_GWS" == false ]; then
  skip "e2e multiple external gateway stale conntrack entry deletion validation"
fi

if [ "$OVN_GATEWAY_MODE" == "shared" ]; then
  # See https://github.com/ovn-org/ovn-kubernetes/issues/4138 for details
  skip "Should ensure load balancer service|LGW"
fi

if [ "$OVN_GATEWAY_MODE" == "local" ]; then
  # See https://github.com/ovn-org/ovn-kubernetes/labels/ci-ipv6 for details
  if [ "$PLATFORM_IPV6_SUPPORT" == true ]; then
    skip "Should be allowed by nodeport services"
    skip "Should successfully create then remove a static pod"
    skip "Should validate connectivity from a pod to a non-node host address on same node"
    skip "Should validate connectivity within a namespace of pods on separate nodes"
    skip "Services"
  fi
fi

# skipping the egress ip legacy health check test because it requires two
# sequenced rollouts of both ovnkube-node and ovnkube-master that take a lot of
# time.
skip "disabling egress nodes impeding Legacy health check"

if [ "$ENABLE_MULTI_NET" != "true" ]; then
  skip "Multi Homing"
fi

if [ "$OVN_NETWORK_QOS_ENABLE" != "true" ]; then
  skip "e2e NetworkQoS validation"
fi

# Only run Node IP/MAC address migration tests if they are explicitly requested
IP_MIGRATION_TESTS="Node IP and MAC address migration"
if [[ "${WHAT}" != "${IP_MIGRATION_TESTS}"* ]]; then
  skip "Node IP and MAC address migration"
fi

# Only run Multi node zones interconnect tests if they are explicitly requested
MULTI_NODE_ZONES_TESTS="Multi node zones interconnect"
if [[ "${WHAT}" != "${MULTI_NODE_ZONES_TESTS}"* ]]; then
  skip "Multi node zones interconnect"
fi

# Only run external gateway tests if they are explicitly requested
EXTERNAL_GATEWAY_TESTS="External Gateway"
if [[ "${WHAT}" != "${EXTERNAL_GATEWAY_TESTS}"* ]]; then
  skip "External Gateway"
fi

# Only run kubevirt virtual machines tests if they are explicitly requested
KV_LIVE_MIGRATION_TESTS="Kubevirt Virtual Machines"
if [[ "${WHAT}" != "${KV_LIVE_MIGRATION_TESTS}"* ]]; then
  skip $KV_LIVE_MIGRATION_TESTS
fi

# Only run network segmentation tests if they are explicitly requested
NETWORK_SEGMENTATION_TESTS="Network Segmentation"
if [[ "${WHAT}" != "${NETWORK_SEGMENTATION_TESTS}"* ]]; then
  skip $NETWORK_SEGMENTATION_TESTS
fi

BGP_TESTS="BGP"
if [ "$ENABLE_ROUTE_ADVERTISEMENTS" != true ]; then
  skip $BGP_TESTS
else
  if [ "$ADVERTISE_DEFAULT_NETWORK" = true ]; then
    # Some test don't work when the default network is advertised, either because
    # the configuration that the test excercises does not make sense for an advertised network, or
    # there is some bug or functional gap
    # call out case by case

    # pod reached from default network through secondary interface, asymetric, configuration does not make sense
    # TODO: perhaps the secondary network attached pods should not be attached to default network
    skip "Multi Homing A single pod with an OVN-K secondary network attached to a localnet network mapped to breth0 can be reached by a client pod in the default network on the same node"
    skip "Multi Homing A single pod with an OVN-K secondary network attached to a localnet network mapped to breth0 can be reached by a client pod in the default network on a different node"
  
    # these tests require metallb but the configuration we do for it is not compatible with the configuration we do to advertise the default network
    # TODO: consolidate configuration
    skip "Load Balancer Service Tests with MetalLB"
    skip "EgressService"

    # tests that specifically expect the node SNAT to happen
    # TODO: expect the pod IP where it makes sense
    skip "e2e egress firewall policy validation with external containers"
    skip "e2e egress IP validation Cluster Default Network \[OVN network\] Using different methods to disable a node's availability for egress Should validate the egress IP functionality against remote hosts"
    skip "e2e egress IP validation Cluster Default Network \[OVN network\] Should validate the egress IP SNAT functionality against host-networked pods"
    skip "e2e egress IP validation Cluster Default Network Should validate egress IP logic when one pod is managed by more than one egressIP object"
    skip "e2e egress IP validation Cluster Default Network Should re-assign egress IPs when node readiness / reachability goes down/up"
    skip "Pod to external server PMTUD when a client ovnk pod targeting an external server is created when tests are run towards the agnhost echo server queries to the hostNetworked server pod on another node shall work for UDP"

    # https://issues.redhat.com/browse/OCPBUGS-55028
    skip "e2e egress IP validation Cluster Default Network \[secondary-host-eip\]"

    # https://issues.redhat.com/browse/OCPBUGS-50636
    skip "Services of type NodePort should listen on each host addresses"
    skip "Services of type NodePort should work on secondary node interfaces for ETP=local and ETP=cluster when backend pods are also served by EgressIP"

    # https://github.com/ovn-kubernetes/ovn-kubernetes/issues/5240
    skip "e2e control plane test node readiness according to its defaults interface MTU size should get node not ready with a too small MTU"

    # buggy tests that don't work in dual stack mode
    skip "Service Hairpin SNAT Should ensure service hairpin traffic is NOT SNATed to hairpin masquerade IP; GR LB"
    skip "Services when a nodePort service targeting a pod with hostNetwork:false is created when tests are run towards the agnhost echo service queries to the nodePort service shall work for TCP"
    skip "Services when a nodePort service targeting a pod with hostNetwork:true is created when tests are run towards the agnhost echo service queries to the nodePort service shall work for TCP"
    skip "Services when a nodePort service targeting a pod with hostNetwork:false is created when tests are run towards the agnhost echo service queries to the nodePort service shall work for UDP"
    skip "Services when a nodePort service targeting a pod with hostNetwork:true is created when tests are run towards the agnhost echo service queries to the nodePort service shall work for UDP"
  fi
fi

# setting these is required to make RuntimeClass tests work ... :/
export KUBE_CONTAINER_RUNTIME=remote
export KUBE_CONTAINER_RUNTIME_ENDPOINT=unix:///run/containerd/containerd.sock
export KUBE_CONTAINER_RUNTIME_NAME=containerd
export NUM_NODES=2

FOCUS=$(echo "${@:1}" | sed 's/ /\\s/g')

# Ginkgo test timeout needs to be lower than both github's timeout and go test
# timeout to be able to get proper Ginkgo output when it happens.
TEST_TIMEOUT=${TEST_TIMEOUT:-180}
GO_TEST_TIMEOUT=$((TEST_TIMEOUT + 5))

pushd e2e

go mod download
go test -test.timeout ${GO_TEST_TIMEOUT}m -v . \
        -ginkgo.v \
        -ginkgo.focus ${FOCUS:-.} \
        -ginkgo.timeout ${TEST_TIMEOUT}m \
        -ginkgo.flake-attempts ${FLAKE_ATTEMPTS:-2} \
        -ginkgo.skip="${SKIPPED_TESTS}" \
        -ginkgo.junit-report=${E2E_REPORT_DIR}/junit_${E2E_REPORT_PREFIX}report.xml \
        -provider skeleton \
        -kubeconfig ${KUBECONFIG} \
        ${NUM_NODES:+"--num-nodes=${NUM_NODES}"} \
        ${E2E_REPORT_DIR:+"--report-dir=${E2E_REPORT_DIR}"}
popd
