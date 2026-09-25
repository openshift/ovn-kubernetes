package test

// This list contains separate lists of informing and blocking tests. Tests not
// on either of these lists do not run. To graduate a test from informing to
// blocking:
//  1. Remove the tests from InformingTests list and add it to the BlockingTests list
//  2. Rebuild: ./hack/build-tests-ext.sh
//  3. Verify: ./bin/ovn-kubernetes-tests-ext list tests | jq -r '.[] | select(.name == "test name here") | .lifecycle'
//
// Used by: openshift/cmd/ovn-kubernetes-tests-ext/main.go
//
// 4.20 only registers tests that exist in this branch's test/e2e. 4.21-only
// tests (EVPN, VTEP, uplink, ClusterNetworkConnect) are omitted.

// InformingTests lists tests that generally pass but are not considered stable
// and should not block CI jobs if they fail.
var InformingTests = []string{
	"[Feature:NetworkSegmentation][ovn-kubernetes-ote][sig-network] Network Segmentation ClusterUserDefinedNetwork CRD Controller pod connected to ClusterUserDefinedNetwork CR & managed NADs cannot be deleted when being used [Suite:ovn-kubernetes/conformance/parallel]",
	"[Feature:NetworkSegmentation][ovn-kubernetes-ote][sig-network] Network Segmentation ClusterUserDefinedNetwork CRD Controller should create NAD according to spec in each target namespace and report active namespaces [Suite:ovn-kubernetes/conformance/parallel]",
	"[Feature:NetworkSegmentation][ovn-kubernetes-ote][sig-network] Network Segmentation ClusterUserDefinedNetwork CRD Controller should create NAD in new created namespaces that apply to namespace-selector [Suite:ovn-kubernetes/conformance/parallel]",
	"[Feature:NetworkSegmentation][ovn-kubernetes-ote][sig-network] Network Segmentation ClusterUserDefinedNetwork CRD Controller when CR is deleted, should delete all managed NAD in each target namespace [Suite:ovn-kubernetes/conformance/parallel]",
	"[Feature:NetworkSegmentation][ovn-kubernetes-ote][sig-network] Network Segmentation ClusterUserDefinedNetwork CRD Controller when namespace-selector is mutated should create NAD in namespaces that apply to mutated namespace-selector [Suite:ovn-kubernetes/conformance/parallel]",
	"[Feature:NetworkSegmentation][ovn-kubernetes-ote][sig-network] Network Segmentation ClusterUserDefinedNetwork CRD Controller when namespace-selector is mutated should delete managed NAD in namespaces that no longer apply to namespace-selector [Suite:ovn-kubernetes/conformance/parallel]",
	"[Feature:NetworkSegmentation][ovn-kubernetes-ote][sig-network] Network Segmentation UserDefinedNetwork CRD Controller for L2 secondary network pod connected to UserDefinedNetwork cannot be deleted when being used [Suite:ovn-kubernetes/conformance/parallel]",
	"[Feature:NetworkSegmentation][ovn-kubernetes-ote][sig-network] Network Segmentation UserDefinedNetwork CRD Controller for L2 secondary network should create NetworkAttachmentDefinition according to spec [Suite:ovn-kubernetes/conformance/parallel]",
	"[Feature:NetworkSegmentation][ovn-kubernetes-ote][sig-network] Network Segmentation UserDefinedNetwork CRD Controller for L2 secondary network should delete NetworkAttachmentDefinition when UserDefinedNetwork is deleted [Suite:ovn-kubernetes/conformance/parallel]",
	"[Feature:NetworkSegmentation][ovn-kubernetes-ote][sig-network] Network Segmentation UserDefinedNetwork CRD Controller for primary UDN without required namespace label should be able to create pod and it will attach to the cluster default network [Suite:ovn-kubernetes/conformance/parallel]",
	"[Feature:NetworkSegmentation][ovn-kubernetes-ote][sig-network] Network Segmentation UserDefinedNetwork CRD Controller for primary UDN without required namespace label should not be able to update the namespace and add the UDN label [Suite:ovn-kubernetes/conformance/parallel]",
	"[Feature:NetworkSegmentation][ovn-kubernetes-ote][sig-network] Network Segmentation UserDefinedNetwork CRD Controller for primary UDN without required namespace label should not be able to update the namespace and remove the UDN label [Suite:ovn-kubernetes/conformance/parallel]",
	"[Feature:NetworkSegmentation][ovn-kubernetes-ote][sig-network] Network Segmentation a user defined primary network created using ClusterUserDefinedNetwork can perform east/west traffic between nodes two pods connected over a L2 primary UDN [Suite:ovn-kubernetes/conformance/parallel]",
	"[Feature:NetworkSegmentation][ovn-kubernetes-ote][sig-network] Network Segmentation a user defined primary network created using ClusterUserDefinedNetwork can perform east/west traffic between nodes two pods connected over a L2 primary UDN with custom network [Suite:ovn-kubernetes/conformance/parallel]",
	"[Feature:NetworkSegmentation][ovn-kubernetes-ote][sig-network] Network Segmentation a user defined primary network created using ClusterUserDefinedNetwork can perform east/west traffic between nodes two pods connected over a L3 primary UDN [Suite:ovn-kubernetes/conformance/parallel]",
	"[Feature:NetworkSegmentation][ovn-kubernetes-ote][sig-network] Network Segmentation a user defined primary network created using ClusterUserDefinedNetwork creates a networkStatus Annotation with UDN interface L2 primary UDN [Suite:ovn-kubernetes/conformance/parallel]",
	"[Feature:NetworkSegmentation][ovn-kubernetes-ote][sig-network] Network Segmentation a user defined primary network created using ClusterUserDefinedNetwork creates a networkStatus Annotation with UDN interface L2 primary UDN with custom network [Suite:ovn-kubernetes/conformance/parallel]",
	"[Feature:NetworkSegmentation][ovn-kubernetes-ote][sig-network] Network Segmentation a user defined primary network created using ClusterUserDefinedNetwork creates a networkStatus Annotation with UDN interface L3 primary UDN [Suite:ovn-kubernetes/conformance/parallel]",
	"[Feature:NetworkSegmentation][ovn-kubernetes-ote][sig-network] Network Segmentation a user defined primary network created using NetworkAttachmentDefinitions can perform east/west traffic between nodes two pods connected over a L2 primary UDN [Suite:ovn-kubernetes/conformance/parallel]",
	"[Feature:NetworkSegmentation][ovn-kubernetes-ote][sig-network] Network Segmentation a user defined primary network created using NetworkAttachmentDefinitions can perform east/west traffic between nodes two pods connected over a L2 primary UDN with custom network [Suite:ovn-kubernetes/conformance/parallel]",
	"[Feature:NetworkSegmentation][ovn-kubernetes-ote][sig-network] Network Segmentation a user defined primary network created using NetworkAttachmentDefinitions can perform east/west traffic between nodes two pods connected over a L3 primary UDN [Suite:ovn-kubernetes/conformance/parallel]",
	"[Feature:NetworkSegmentation][ovn-kubernetes-ote][sig-network] Network Segmentation a user defined primary network created using NetworkAttachmentDefinitions creates a networkStatus Annotation with UDN interface L2 primary UDN [Suite:ovn-kubernetes/conformance/parallel]",
	"[Feature:NetworkSegmentation][ovn-kubernetes-ote][sig-network] Network Segmentation a user defined primary network created using NetworkAttachmentDefinitions creates a networkStatus Annotation with UDN interface L2 primary UDN with custom network [Suite:ovn-kubernetes/conformance/parallel]",
	"[Feature:NetworkSegmentation][ovn-kubernetes-ote][sig-network] Network Segmentation a user defined primary network created using NetworkAttachmentDefinitions creates a networkStatus Annotation with UDN interface L3 primary UDN [Suite:ovn-kubernetes/conformance/parallel]",
	"[Feature:NetworkSegmentation][ovn-kubernetes-ote][sig-network] Network Segmentation a user defined primary network created using UserDefinedNetwork can perform east/west traffic between nodes two pods connected over a L2 primary UDN [Suite:ovn-kubernetes/conformance/parallel]",
	"[Feature:NetworkSegmentation][ovn-kubernetes-ote][sig-network] Network Segmentation a user defined primary network created using UserDefinedNetwork can perform east/west traffic between nodes two pods connected over a L2 primary UDN with custom network [Suite:ovn-kubernetes/conformance/parallel]",
	"[Feature:NetworkSegmentation][ovn-kubernetes-ote][sig-network] Network Segmentation a user defined primary network created using UserDefinedNetwork can perform east/west traffic between nodes two pods connected over a L3 primary UDN [Suite:ovn-kubernetes/conformance/parallel]",
	"[Feature:NetworkSegmentation][ovn-kubernetes-ote][sig-network] Network Segmentation a user defined primary network created using UserDefinedNetwork creates a networkStatus Annotation with UDN interface L2 primary UDN [Suite:ovn-kubernetes/conformance/parallel]",
	"[Feature:NetworkSegmentation][ovn-kubernetes-ote][sig-network] Network Segmentation a user defined primary network created using UserDefinedNetwork creates a networkStatus Annotation with UDN interface L2 primary UDN with custom network [Suite:ovn-kubernetes/conformance/parallel]",
	"[Feature:NetworkSegmentation][ovn-kubernetes-ote][sig-network] Network Segmentation a user defined primary network created using UserDefinedNetwork creates a networkStatus Annotation with UDN interface L3 primary UDN [Suite:ovn-kubernetes/conformance/parallel]",
	"[Feature:NetworkSegmentation][ovn-kubernetes-ote][sig-network] Network Segmentation a user defined primary network doesn't cause network name conflict [Suite:ovn-kubernetes/conformance/parallel]",
	"[Feature:NetworkSegmentation][ovn-kubernetes-ote][sig-network] Network Segmentation when primary network exist, ClusterUserDefinedNetwork status should report not-ready [Suite:ovn-kubernetes/conformance/parallel]",
	"[Feature:NetworkSegmentation][ovn-kubernetes-ote][sig-network] Network Segmentation when primary network exist, UserDefinedNetwork status should report not-ready [Suite:ovn-kubernetes/conformance/parallel]",
	"[Feature:NetworkSegmentation][ovn-kubernetes-ote][sig-network] Network Segmentation: Network Policies on a user defined primary network pods within namespace should be isolated when deny policy is present in L2 dualstack primary UDN [Suite:ovn-kubernetes/conformance/parallel]",
	"[Feature:NetworkSegmentation][ovn-kubernetes-ote][sig-network] Network Segmentation: Network Policies on a user defined primary network pods within namespace should be isolated when deny policy is present in L2 dualstack primary UDN with custom network [Suite:ovn-kubernetes/conformance/parallel]",
	"[Feature:NetworkSegmentation][ovn-kubernetes-ote][sig-network] Network Segmentation: Network Policies on a user defined primary network pods within namespace should be isolated when deny policy is present in L3 dualstack primary UDN [Suite:ovn-kubernetes/conformance/parallel]",
	"[Feature:NetworkSegmentation][ovn-kubernetes-ote][sig-network] Network Segmentation: Preconfigured Layer2 UDN duplicate IP validation with primary UDN layer 2 pods should fail when creating second pod with duplicate static IP IPv4 duplicate [Suite:ovn-kubernetes/conformance/parallel]",
	"[Feature:NetworkSegmentation][ovn-kubernetes-ote][sig-network] Network Segmentation: Preconfigured Layer2 UDN duplicate IP validation with primary UDN layer 2 pods should fail when creating second pod with duplicate static IP IPv6 duplicate [Suite:ovn-kubernetes/conformance/parallel]",
	"[Feature:NetworkSegmentation][ovn-kubernetes-ote][sig-network] Network Segmentation: Preconfigured Layer2 UDN should respect network configuration Layer2 basic configuration [Suite:ovn-kubernetes/conformance/parallel]",
	"[Feature:NetworkSegmentation][ovn-kubernetes-ote][sig-network] Network Segmentation: Preconfigured Layer2 UDN should respect network configuration Layer2 with custom subnets [Suite:ovn-kubernetes/conformance/parallel]",
	"[Feature:NetworkSegmentation][ovn-kubernetes-ote][sig-network] Network Segmentation: Preconfigured Layer2 UDN should respect network configuration Layer2 with inverted gateway/management IPs [Suite:ovn-kubernetes/conformance/parallel]",
	"[Feature:NetworkSegmentation][ovn-kubernetes-ote][sig-network] Network Segmentation: services on a user defined primary network should be reachable through their cluster IP, node port and load balancer L2 primary UDN with custom network, cluster-networked pods, NodePort service [Suite:ovn-kubernetes/conformance/parallel]",
}

// BlockingTests lists tests that are considered stable and should block CI jobs
// if they fail.
var BlockingTests = []string{}
