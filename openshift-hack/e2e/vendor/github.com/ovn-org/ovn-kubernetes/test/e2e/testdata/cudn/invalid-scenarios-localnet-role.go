package cudn

import "github.com/ovn-org/ovn-kubernetes/test/e2e/testdata"

var LocalnetInvalidRole = []testdata.ValidateCRScenario{
	{
		Description: "role unset",
		ExpectedErr: `spec.network.localnet.role: Required value`,
		Manifest: `
apiVersion: k8s.ovn.org/v1
kind: ClusterUserDefinedNetwork
metadata:
  name: localnet-role-unset-should-fail
spec:
  namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: red}}
  network:
    topology: Localnet
    localnet:
      physicalNetworkName: test
      subnets: [10.0.0.0/24]`,
	},
	{
		Description: "role is primary",
		ExpectedErr: `spec.network.localnet.role: Unsupported value: "Primary": supported values: "Secondary"`,
		Manifest: `
---
apiVersion: k8s.ovn.org/v1
kind: ClusterUserDefinedNetwork
metadata:
  name: localnet-role-primary-should-fail
spec:
  namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: red}}
  network:
    topology: Localnet
    localnet:
      role: Primary
      physicalNetworkName: test
      subnets: [10.0.0.0/24]`,
	},
}
