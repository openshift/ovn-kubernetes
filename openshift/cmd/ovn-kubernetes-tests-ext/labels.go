package main

import (
	"sort"

	"k8s.io/apimachinery/pkg/util/sets"
)

// getTestExtensionLabels returns labels that should be applied to all tests in this extension
func getTestExtensionLabels() []string {
	return []string{"sig-network", "ovn-kubernetes-ote"}
}

// generatePrependedLabelsStr generates labels that are prepended to a test name
func generatePrependedLabelsStr(labels sets.Set[string]) string {
	labelList := labels.UnsortedList()
	sort.Strings(labelList)

	var labelsStr = ""
	for _, label := range labelList {
		labelsStr += "[" + label + "]"
	}
	return labelsStr
}
