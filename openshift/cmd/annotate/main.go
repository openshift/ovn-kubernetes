package main

import (
	"github.com/ovn-kubernetes/ovn-kubernetes/openshift/test/annotate"
	ocpdeploymentconfig "github.com/ovn-kubernetes/ovn-kubernetes/openshift/test/deploymentconfig"
	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/deploymentconfig"
)

func main() {
	deploymentconfig.Set(ocpdeploymentconfig.New(nil))
	annotate.Run(annotate.LabelToTestNameMatchMaps, annotate.LabelToLabelMaps, func(name string) bool { return false })
}
