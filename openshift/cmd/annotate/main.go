package main

import (
	"github.com/ovn-kubernetes/ovn-kubernetes/openshift/test/annotate"
	ocpdeploymentconfig "github.com/ovn-kubernetes/ovn-kubernetes/openshift/test/deploymentconfig"
	ocpinfraprovider "github.com/ovn-kubernetes/ovn-kubernetes/openshift/test/infraprovider"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/infraprovider"
)

func main() {
	deploymentconfig.Set(ocpdeploymentconfig.New(nil))
	infraprovider.Set(&ocpinfraprovider.OpenshiftInfraProvider{})
	annotate.Run(annotate.LabelToTestNameMatchMaps, annotate.LabelToLabelMaps, func(name string) bool { return false })
}
