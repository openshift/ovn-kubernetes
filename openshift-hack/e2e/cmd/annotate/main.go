package main

import (
	annotate "github.com/openshift/ovn-kubernetes/openshift-hack/e2e/pkg/annotate"
)

func main() {
	annotate.Run(annotate.TestMaps, func(name string) bool { return false })
}
