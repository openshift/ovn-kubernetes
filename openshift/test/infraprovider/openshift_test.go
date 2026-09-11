package infraprovider

import (
	"testing"

	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider/api"
)

// A nil clusterInfra models a cloud platform (e.g. Azure) where no external
// container infrastructure exists. Historically these methods panicked with
// "not implemented", which crashed the test binary instead of failing
// gracefully. They must now return an error (OCPBUGS-113964).
func TestExternalContainerMethodsReturnErrorWhenUnavailable(t *testing.T) {
	o := &OpenshiftInfraProvider{} // clusterInfra is nil

	if _, err := o.ExecExternalContainerCommand(api.ExternalContainer{Name: "frr"}, []string{"true"}); err == nil {
		t.Error("ExecExternalContainerCommand: expected error when clusterInfra is nil, got nil")
	}
	if _, err := o.GetExternalContainerNetworkInterface(api.ExternalContainer{Name: "frr"}, nil); err == nil {
		t.Error("GetExternalContainerNetworkInterface: expected error when clusterInfra is nil, got nil")
	}
	if _, err := o.GetExternalContainerLogs(api.ExternalContainer{Name: "frr"}); err == nil {
		t.Error("GetExternalContainerLogs: expected error when clusterInfra is nil, got nil")
	}
	if _, err := o.ListNetworks(); err == nil {
		t.Error("ListNetworks: expected error when clusterInfra is nil, got nil")
	}
}

// IsExternalContainerAvailable gates external container connectivity checks in
// the e2e tests. It must report false on platforms without external container
// infrastructure (clusterInfra nil) and true otherwise.
func TestIsExternalContainerAvailable(t *testing.T) {
	if (&OpenshiftInfraProvider{}).IsExternalContainerAvailable() {
		t.Error("expected IsExternalContainerAvailable to be false when clusterInfra is nil")
	}
	if !(&OpenshiftInfraProvider{clusterInfra: &baremetalInfra{}}).IsExternalContainerAvailable() {
		t.Error("expected IsExternalContainerAvailable to be true when clusterInfra is set")
	}
}
