package main

import (
	"k8s.io/apimachinery/pkg/util/sets"
)

// generatePrependedLabelsStr generates labels that are prepended to a test name. Always add networking label. Add all
// labels in set.
func generatePrependedLabelsStr(labels sets.Set[string]) string {
	var labelsStr = "[" + getNetworkingLabel() + "]" // always apply networking label
	for _, label := range labels.UnsortedList() {
		labelsStr += "[" + label + "]"
	}
	return labelsStr
}

func getNetworkingLabel() string {
	return "networking"
}
