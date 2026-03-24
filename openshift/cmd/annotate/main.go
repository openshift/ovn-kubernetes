package main

import (
	"github.com/ovn-kubernetes/ovn-kubernetes/openshift/test/annotate"
)

func main() {
	annotate.Run(annotate.LabelToTestNameMatchMaps, annotate.LabelToLabelMaps, func(name string) bool { return false })
}
