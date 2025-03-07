package ocpfeaturegate

import (
	"github.com/ovn-org/ovn-kubernetes/test/e2e/label"
)

const OCPFeatureGateLabelName = "OCPFeatureGate"

var (
	NetworkSegmentation = newFeatureGate("NetworkSegmentation")
)

func newFeatureGate(name string) label.Label {
	return label.NewLabel(OCPFeatureGateLabelName, name)
}
